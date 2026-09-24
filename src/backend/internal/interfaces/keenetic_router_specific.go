//go:build entware_kn

package interfaces

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"magitrickle/models"
)

const (
	keeneticRCIBaseURL = "http://127.0.0.1:79"
	keeneticRCITimeout = 2 * time.Second
)

type KeeneticRouterSpecificAPI struct {
	BaseURL string
	Client  *http.Client
}

type keeneticInterfaceMeta struct {
	Description   string `json:"description"`
	InterfaceName string `json:"interface-name"`
}

type keeneticInterfaceSystemNameRequest struct {
	Show struct {
		Interface struct {
			Name       string `json:"name"`
			Details    string `json:"details"`
			SystemName string `json:"system-name"`
		} `json:"interface"`
	} `json:"show"`
}

type keeneticInterfaceSystemNameResponse struct {
	Show struct {
		Interface struct {
			SystemName string `json:"system-name"`
		} `json:"interface"`
	} `json:"show"`
}

type keeneticInternetPolicy struct {
	Description string          `json:"description"`
	Table       json.RawMessage `json:"table"`
	Table4      json.RawMessage `json:"table4"`
	Table6      json.RawMessage `json:"table6"`
}

func NewKeeneticRouterSpecificAPI() *KeeneticRouterSpecificAPI {
	return &KeeneticRouterSpecificAPI{
		BaseURL: keeneticRCIBaseURL,
		Client:  &http.Client{Timeout: keeneticRCITimeout},
	}
}

func (a *KeeneticRouterSpecificAPI) GetIfaceAliases() (map[string]string, error) {
	client := a.httpClient()
	baseURL := a.baseURL()

	interfaces, err := a.interfaceList(client, baseURL)
	if err != nil {
		return nil, err
	}

	interfaceIDs := make([]string, 0, len(interfaces))
	for interfaceID := range interfaces {
		interfaceIDs = append(interfaceIDs, interfaceID)
	}

	systemNames, err := a.interfaceSystemNames(client, baseURL, interfaceIDs)
	if err != nil {
		return nil, err
	}

	aliases := make(map[string]string, len(systemNames))
	for interfaceID, systemName := range systemNames {
		if systemName == "" {
			continue
		}

		meta := interfaces[interfaceID]
		alias := strings.TrimSpace(meta.Description)
		if alias == "" {
			alias = strings.TrimSpace(meta.InterfaceName)
		}
		if alias == "" || alias == systemName {
			continue
		}

		aliases[systemName] = alias
	}

	return aliases, nil
}

func (a *KeeneticRouterSpecificAPI) GetInternetPolicies() ([]models.InterfaceInfo, error) {
	policies, err := a.internetPolicies()
	if err != nil {
		return nil, err
	}

	names := make([]string, 0, len(policies))
	for name := range policies {
		names = append(names, name)
	}
	sort.Strings(names)

	result := make([]models.InterfaceInfo, 0, len(names))
	for _, name := range names {
		policy := policies[name]
		description := strings.TrimSpace(policy.Description)
		if description == "" {
			description = name
		}
		result = append(result, models.InterfaceInfo{
			ID:   models.KeeneticPolicyTarget(name),
			Name: description,
			Kind: "policy",
		})
	}
	return result, nil
}

func (a *KeeneticRouterSpecificAPI) GetInternetPolicyRouteTables(name string) (PolicyRouteTables, error) {
	policies, err := a.internetPolicies()
	if err != nil {
		return PolicyRouteTables{}, err
	}
	policy, exists := policies[name]
	if !exists {
		return PolicyRouteTables{}, fmt.Errorf("Keenetic Internet access policy %q does not exist", name)
	}

	tables := PolicyRouteTables{}
	tables.IPv4, err = parsePolicyTableID(policy.Table4)
	if err != nil {
		return PolicyRouteTables{}, fmt.Errorf("invalid IPv4 table for Keenetic policy %q: %w", name, err)
	}
	tables.IPv6, err = parsePolicyTableID(policy.Table6)
	if err != nil {
		return PolicyRouteTables{}, fmt.Errorf("invalid IPv6 table for Keenetic policy %q: %w", name, err)
	}

	// Older KeeneticOS versions report one shared table ID instead of table4/table6.
	if tables.IPv4 == 0 && tables.IPv6 == 0 && len(policy.Table) > 0 {
		legacyTable, err := parsePolicyTableID(policy.Table)
		if err != nil {
			return PolicyRouteTables{}, fmt.Errorf("invalid routing table for Keenetic policy %q: %w", name, err)
		}
		tables.IPv4, tables.IPv6 = legacyTable, legacyTable
	}
	return tables, nil
}

func (a *KeeneticRouterSpecificAPI) internetPolicies() (map[string]keeneticInternetPolicy, error) {
	client := a.httpClient()
	resp, err := client.Get(a.baseURL() + "/rci/show/ip/policy")
	if err != nil {
		return nil, fmt.Errorf("request Keenetic Internet access policies: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected Internet access policy status: %s", resp.Status)
	}

	var payload map[string]json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("decode Keenetic Internet access policies: %w", err)
	}
	// Some KeeneticOS releases wrap show-command output in a "policy" object.
	if wrapped, exists := payload["policy"]; exists {
		var policies map[string]json.RawMessage
		if err := json.Unmarshal(wrapped, &policies); err != nil {
			return nil, fmt.Errorf("decode wrapped Keenetic Internet access policies: %w", err)
		}
		payload = policies
	}

	policies := make(map[string]keeneticInternetPolicy, len(payload))
	for name, raw := range payload {
		var policy keeneticInternetPolicy
		if err := json.Unmarshal(raw, &policy); err != nil {
			return nil, fmt.Errorf("decode Keenetic Internet access policy %q: %w", name, err)
		}
		policies[name] = policy
	}
	return policies, nil
}

func parsePolicyTableID(raw json.RawMessage) (int, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return 0, nil
	}
	var table int
	if err := json.Unmarshal(raw, &table); err == nil {
		return table, nil
	}
	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		return 0, err
	}
	table, err := strconv.Atoi(strings.TrimSpace(text))
	if err != nil || table < 0 {
		return 0, fmt.Errorf("expected a non-negative integer, got %q", text)
	}
	return table, nil
}

func (a *KeeneticRouterSpecificAPI) httpClient() *http.Client {
	if a != nil && a.Client != nil {
		return a.Client
	}
	return &http.Client{Timeout: keeneticRCITimeout}
}

func (a *KeeneticRouterSpecificAPI) baseURL() string {
	if a != nil && a.BaseURL != "" {
		return strings.TrimRight(a.BaseURL, "/")
	}
	return keeneticRCIBaseURL
}

func (a *KeeneticRouterSpecificAPI) interfaceList(client *http.Client, baseURL string) (map[string]keeneticInterfaceMeta, error) {
	resp, err := client.Get(baseURL + "/rci/show/interface")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected interface list status: %s", resp.Status)
	}

	var payload map[string]json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("decode interface list: %w", err)
	}

	interfaces := make(map[string]keeneticInterfaceMeta, len(payload))
	for interfaceID, raw := range payload {
		var meta keeneticInterfaceMeta
		if err := json.Unmarshal(raw, &meta); err != nil {
			continue
		}

		interfaces[interfaceID] = meta
	}

	return interfaces, nil
}

func (a *KeeneticRouterSpecificAPI) interfaceSystemNames(client *http.Client, baseURL string, interfaceIDs []string) (map[string]string, error) {
	if len(interfaceIDs) == 0 {
		return map[string]string{}, nil
	}

	requests := make([]keeneticInterfaceSystemNameRequest, len(interfaceIDs))
	for i, interfaceID := range interfaceIDs {
		requests[i].Show.Interface.Name = interfaceID
		requests[i].Show.Interface.Details = "yes"
		requests[i].Show.Interface.SystemName = "yes"
	}

	body, err := json.Marshal(requests)
	if err != nil {
		return nil, fmt.Errorf("encode interface system-name request: %w", err)
	}

	resp, err := client.Post(baseURL+"/rci/", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected system-name status: %s", resp.Status)
	}

	var payload []keeneticInterfaceSystemNameResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("decode system-name: %w", err)
	}

	systemNames := make(map[string]string, len(interfaceIDs))
	for i, item := range payload {
		if i >= len(interfaceIDs) {
			break
		}

		systemName := strings.TrimSpace(item.Show.Interface.SystemName)
		if systemName == "" {
			continue
		}

		systemNames[interfaceIDs[i]] = systemName
	}

	return systemNames, nil
}
