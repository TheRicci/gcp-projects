package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"strconv"
)

type Receiver interface {
	ServerStart(ctx context.Context)
	CatchEvent() (*Alert, error)
}

type Engine struct {
	receiver   Receiver
	sharedData *SharedData
	store      AlertStore
}

func NewEngine(recv Receiver, sharedData *SharedData, store AlertStore) *Engine {
	if sharedData == nil {
		sharedData = NewSharedData()
	}
	ensureSharedData(sharedData)
	return &Engine{
		receiver:   recv,
		sharedData: sharedData,
		store:      store,
	}
}

func (e *Engine) Run(ctx context.Context) error {
	e.receiver.ServerStart(ctx)
	e.refreshGauges()

	for {
		alert, err := e.receiver.CatchEvent()
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return nil
			}
			log.Printf("receiver error: %v", err)
			continue
		}
		if alert == nil {
			continue
		}

		e.observeAlert(alert)
		e.mergeAlert(alert)
		e.refreshGauges()

		if err := e.store.SaveAlert(ctx, alert); err != nil {
			log.Printf("failed to store alert: %v", err)
			StorageWriteErrors.Inc()
		}
	}
}

func (e *Engine) Bootstrap(ctx context.Context, limit int) error {
	alerts, err := e.store.LoadRecentAlerts(ctx, limit)
	if err != nil {
		return err
	}
	for _, alert := range alerts {
		e.mergeAlert(alert)
	}
	e.refreshGauges()
	log.Printf("rebuilt in-memory state from %d Firestore alerts", len(alerts))
	return nil
}

func (e *Engine) observeAlert(alert *Alert) {
	logType := stringValue(alert.LogType)
	tier := intLabel(alert.Tier)
	severity := intLabel(alert.Severity)

	AlertsTotal.WithLabelValues(logType, tier, severity).Inc()
	SeverityDistribution.WithLabelValues(severity).Inc()
	TierDistribution.WithLabelValues(tier).Inc()
}

func (e *Engine) mergeAlert(alert *Alert) {
	idsKey := fmt.Sprintf("%s-%s-%s", alert.IP, stringValue(alert.Threat), stringValue(alert.LogType))
	currentIDSAlert := e.sharedData.IDSAlertsMap[idsKey]
	if currentIDSAlert == nil {
		e.sharedData.IDSAlertsMap[idsKey] = alert
		currentIDSAlert = alert
	}

	currentIDSAlert.LastTimestamp = alert.FirstTimestamp
	switch alertSource(alert) {
	case "suricata":
		appendOrUpdate(&e.sharedData.SuricataList, currentIDSAlert, currentIDSAlert != alert, func() {
			currentIDSAlert.Suricata = append(currentIDSAlert.Suricata, alert.Suricata...)
		})
		sortAlertsByTimestamp(e.sharedData.SuricataList)
	case "modsec":
		appendOrUpdate(&e.sharedData.ModsecList, currentIDSAlert, currentIDSAlert != alert, func() {
			currentIDSAlert.Modsec = append(currentIDSAlert.Modsec, alert.Modsec...)
		})
		sortAlertsByTimestamp(e.sharedData.ModsecList)
	case "wazuh":
		appendOrUpdate(&e.sharedData.WazuhList, currentIDSAlert, currentIDSAlert != alert, func() {
			currentIDSAlert.Wazuh = append(currentIDSAlert.Wazuh, alert.Wazuh...)
		})
		sortAlertsByTimestamp(e.sharedData.WazuhList)
	}

	alertsKey := fmt.Sprintf("%s-%d-%d", alert.IP, intValue(alert.DstPort), intValue(alert.Tier))
	currentAlert := e.sharedData.AlertsMap[alertsKey]
	if currentAlert == nil {
		aggregated := *alert
		aggregated.Threat = nil
		e.sharedData.AlertsMap[alertsKey] = &aggregated
		e.sharedData.AlertsList = append(e.sharedData.AlertsList, &aggregated)
		sortAlertsByTimestamp(e.sharedData.AlertsList)
		return
	}

	currentAlert.LastTimestamp = alert.FirstTimestamp
	currentAlert.Quantity += alert.Quantity
	currentAlert.Suricata = append(currentAlert.Suricata, alert.Suricata...)
	currentAlert.Modsec = append(currentAlert.Modsec, alert.Modsec...)
	currentAlert.Wazuh = append(currentAlert.Wazuh, alert.Wazuh...)
	sortAlertsByTimestamp(e.sharedData.AlertsList)
}

func (e *Engine) refreshGauges() {
	UniqueIPs.Set(float64(len(e.sharedData.AlertsMap)))
	AlertsBySource.WithLabelValues("suricata").Set(float64(len(e.sharedData.SuricataList)))
	AlertsBySource.WithLabelValues("modsec").Set(float64(len(e.sharedData.ModsecList)))
	AlertsBySource.WithLabelValues("wazuh").Set(float64(len(e.sharedData.WazuhList)))
}

func appendOrUpdate(alerts *[]*Alert, alert *Alert, existing bool, update func()) {
	if existing {
		alert.Quantity++
		update()
		return
	}
	*alerts = append(*alerts, alert)
}

func sortAlertsByTimestamp(alerts []*Alert) {
	sort.Slice(alerts, func(i, j int) bool {
		if alerts[j].LastTimestamp == nil {
			return true
		}
		if alerts[i].LastTimestamp == nil {
			return false
		}
		return alerts[i].LastTimestamp.After(*alerts[j].LastTimestamp)
	})
}

func ensureSharedData(data *SharedData) {
	if data.AlertsList == nil {
		data.AlertsList = []*Alert{}
	}
	if data.SuricataList == nil {
		data.SuricataList = []*Alert{}
	}
	if data.ModsecList == nil {
		data.ModsecList = []*Alert{}
	}
	if data.WazuhList == nil {
		data.WazuhList = []*Alert{}
	}
	if data.AlertsMap == nil {
		data.AlertsMap = map[string]*Alert{}
	}
	if data.IDSAlertsMap == nil {
		data.IDSAlertsMap = map[string]*Alert{}
	}
}

func stringValue(v *string) string {
	if v == nil {
		return "unknown"
	}
	return *v
}

func intValue(v *int) int {
	if v == nil {
		return 0
	}
	return *v
}

func intLabel(v *int) string {
	if v == nil {
		return "unknown"
	}
	return strconv.Itoa(*v)
}

func alertSource(alert *Alert) string {
	if alert.LogType != nil {
		return *alert.LogType
	}
	switch {
	case len(alert.Suricata) > 0:
		return "suricata"
	case len(alert.Modsec) > 0:
		return "modsec"
	case len(alert.Wazuh) > 0:
		return "wazuh"
	default:
		return "unknown"
	}
}
