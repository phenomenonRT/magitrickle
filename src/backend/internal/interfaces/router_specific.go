package interfaces

import "magitrickle/models"

type PolicyRouteTables struct {
	IPv4 int
	IPv6 int
}

type RouterSpecificAPI interface {
	GetIfaceAliases() (map[string]string, error)
	GetInternetPolicies() ([]models.InterfaceInfo, error)
	GetInternetPolicyRouteTables(name string) (PolicyRouteTables, error)
}

var routerAPI RouterSpecificAPI

func init() {
	routerAPI = initRouterSpecificAPI()
}

type DummyRouterSpecificAPI struct{}

func (DummyRouterSpecificAPI) GetIfaceAliases() (map[string]string, error) {
	return map[string]string{}, nil
}

func (DummyRouterSpecificAPI) GetInternetPolicies() ([]models.InterfaceInfo, error) {
	return nil, nil
}

func (DummyRouterSpecificAPI) GetInternetPolicyRouteTables(string) (PolicyRouteTables, error) {
	return PolicyRouteTables{}, nil
}

func GetInternetPolicyRouteTables(name string) (PolicyRouteTables, error) {
	return routerAPI.GetInternetPolicyRouteTables(name)
}
