package huaweidns

import (
	caddy "github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	hdns "github.com/jicjoy/huaweidns"
)

// Provider wraps the provider implementation as a Caddy module.
type Provider struct{ *hdns.Provider }

func init() {
	caddy.RegisterModule(Provider{})
}

// CaddyModule returns the Caddy module information.
func (Provider) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dns.providers.huaweidns",
		New: func() caddy.Module { return &Provider{new(hdns.Provider)} },
	}
}

// Before using the provider config, resolve placeholders in the API token.
// Implements caddy.Provisioner.
func (p *Provider) Provision(ctx caddy.Context) error {
	repl := caddy.NewReplacer()
	p.Provider.AccKeyID = repl.ReplaceAll(p.Provider.AccKeyID, "")
	p.Provider.AccKeySecret = repl.ReplaceAll(p.Provider.AccKeySecret, "")
	p.Provider.RegionID = repl.ReplaceAll(p.Provider.RegionID, "")
	return nil
}

// UnmarshalCaddyfile sets up the DNS provider from Caddyfile tokens. Syntax:
//
//		huaweidns {
//		    access_key_id "<access_key_id>"
//		    access_key_secret "<access_key_secret>"
//	     region_id    "<region_id>"
//		}
func (p *Provider) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.NextArg() {
			return d.ArgErr()
		}
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			switch d.Val() {
			case "secret_id":
				if d.NextArg() {
					p.Provider.AccKeyID = d.Val()
				}
				if d.NextArg() {
					return d.ArgErr()
				}
			case "secret_key":
				if d.NextArg() {
					p.Provider.AccKeySecret = d.Val()
				}
				if d.NextArg() {
					return d.ArgErr()
				}
			case "region_id":
				if d.NextArg() {
					p.Provider.RegionID = d.Val()
				}
				if d.NextArg() {
					return d.ArgErr()
				}
			default:
				return d.Errf("unrecognized subdirective '%s'", d.Val())
			}
		}
	}
	if p.AccKeySecret == "" || p.AccKeyID == "" {
		return d.Err("SecretId or SecretKey is empty")
	}
	return nil
}

// Interface guards
var (
	_ caddyfile.Unmarshaler = (*Provider)(nil)
	_ caddy.Provisioner     = (*Provider)(nil)
)
