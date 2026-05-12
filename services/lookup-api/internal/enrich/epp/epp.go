package epp

import (
	"strings"

	"github.com/xmzo/whoice/services/lookup-api/internal/model"
)

type info struct {
	Label       string
	Category    string
	Description string
}

var statuses = map[string]info{
	"ok": {
		Label:       "ok",
		Category:    "ok",
		Description: "The domain has no pending operations or prohibitions.",
	},
	"active": {
		Label:       "active",
		Category:    "ok",
		Description: "The domain is active and delegated.",
	},
	"inactive": {
		Label:       "inactive",
		Category:    "redemption",
		Description: "The domain is not delegated and may not resolve.",
	},
	"addperiod": {
		Label:       "addPeriod",
		Category:    "grace",
		Description: "The domain is inside the initial registration grace period.",
	},
	"autorenewperiod": {
		Label:       "autoRenewPeriod",
		Category:    "grace",
		Description: "The domain is inside the automatic renewal grace period.",
	},
	"renewperiod": {
		Label:       "renewPeriod",
		Category:    "grace",
		Description: "The domain is inside a renewal grace period.",
	},
	"transferperiod": {
		Label:       "transferPeriod",
		Category:    "grace",
		Description: "The domain is inside the grace period after a transfer.",
	},
	"clienttransferprohibited": {
		Label:       "clientTransferProhibited",
		Category:    "client",
		Description: "The registrar has locked the domain to prevent transfer.",
	},
	"clientdeleteprohibited": {
		Label:       "clientDeleteProhibited",
		Category:    "client",
		Description: "The registrar has locked the domain to prevent deletion.",
	},
	"clientupdateprohibited": {
		Label:       "clientUpdateProhibited",
		Category:    "client",
		Description: "The registrar has locked the domain to prevent updates.",
	},
	"clienthold": {
		Label:       "clientHold",
		Category:    "client",
		Description: "The registrar has suspended DNS publication for the domain.",
	},
	"clientrenewprohibited": {
		Label:       "clientRenewProhibited",
		Category:    "client",
		Description: "The registrar has locked the domain to prevent renewal.",
	},
	"servertransferprohibited": {
		Label:       "serverTransferProhibited",
		Category:    "server",
		Description: "The registry has locked the domain to prevent transfer.",
	},
	"serverdeleteprohibited": {
		Label:       "serverDeleteProhibited",
		Category:    "server",
		Description: "The registry has locked the domain to prevent deletion.",
	},
	"serverhold": {
		Label:       "serverHold",
		Category:    "server",
		Description: "The registry has suspended DNS publication for the domain.",
	},
	"serverrenewprohibited": {
		Label:       "serverRenewProhibited",
		Category:    "server",
		Description: "The registry has locked the domain to prevent renewal.",
	},
	"serverupdateprohibited": {
		Label:       "serverUpdateProhibited",
		Category:    "server",
		Description: "The registry has locked the domain to prevent updates.",
	},
	"pendingcreate": {
		Label:       "pendingCreate",
		Category:    "pending",
		Description: "A create operation is being processed.",
	},
	"pendingdelete": {
		Label:       "pendingDelete",
		Category:    "pending",
		Description: "The domain is pending deletion.",
	},
	"pendingrenew": {
		Label:       "pendingRenew",
		Category:    "pending",
		Description: "A renewal operation is being processed.",
	},
	"pendingrestore": {
		Label:       "pendingRestore",
		Category:    "pending",
		Description: "A restore operation is waiting for registry processing.",
	},
	"pendingtransfer": {
		Label:       "pendingTransfer",
		Category:    "pending",
		Description: "A transfer operation is waiting for approval or rejection.",
	},
	"pendingupdate": {
		Label:       "pendingUpdate",
		Category:    "pending",
		Description: "An update operation is being processed.",
	},
	"redemptionperiod": {
		Label:       "redemptionPeriod",
		Category:    "redemption",
		Description: "The domain has been deleted but may still be restorable.",
	},
}

func Apply(result *model.LookupResult) {
	for i := range result.Statuses {
		normalized := normalize(result.Statuses[i].Code)
		info, ok := statuses[normalized]
		if !ok {
			if result.Statuses[i].Label == "" {
				result.Statuses[i].Label = result.Statuses[i].Code
			}
			if result.Statuses[i].URL == "" {
				result.Statuses[i].URL = "https://icann.org/epp"
			}
			continue
		}
		result.Statuses[i].Label = info.Label
		result.Statuses[i].Category = info.Category
		result.Statuses[i].Description = info.Description
		result.Statuses[i].URL = "https://icann.org/epp#" + info.Label
	}
}

func normalize(value string) string {
	value = strings.TrimSpace(value)
	for _, field := range strings.Fields(value) {
		if strings.Contains(strings.ToLower(field), "icann.org/epp#") {
			value = field
			break
		}
	}
	value = strings.ToLower(strings.Trim(value, " ."))
	value = strings.TrimPrefix(value, "https://icann.org/epp#")
	value = strings.TrimPrefix(value, "http://icann.org/epp#")
	replacer := strings.NewReplacer(" ", "", "-", "", "_", "")
	return replacer.Replace(value)
}
