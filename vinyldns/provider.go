/*
Copyright 2018 Comcast Cable Communications Management, LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package vinyldns

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
	"github.com/willswire/go-vinyldns/vinyldns"
)

// Provider returns a schema.Provider for VinylDNS.
func Provider() terraform.ResourceProvider {
	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			"access_key": &schema.Schema{
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: envDefaultFunc("VINYLDNS_ACCESS_KEY"),
			},
			"secret_key": &schema.Schema{
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: envDefaultFunc("VINYLDNS_SECRET_KEY"),
			},
			"host": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: envDefaultFunc("VINYLDNS_HOST"),
			},
			"client_cert": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: envDefaultFuncAllowMissing("VINYLDNS_CLIENT_CERT"),
			},
		},

		ResourcesMap: map[string]*schema.Resource{
			"vinyldns_group":      resourceVinylDNSGroup(),
			"vinyldns_zone":       resourceVinylDNSZone(),
			"vinyldns_record_set": resourceVinylDNSRecordSet(),
		},

		DataSourcesMap: map[string]*schema.Resource{
			"vinyldns_zone": dataSourceVinylDNSZone(),
		},

		ConfigureFunc: providerConfigure,
	}
}

func envDefaultFunc(k string) schema.SchemaDefaultFunc {
	return func() (interface{}, error) {
		if v := os.Getenv(k); v != "" {
			return v, nil
		}

		return nil, nil
	}
}

func envDefaultFuncAllowMissing(k string) schema.SchemaDefaultFunc {
	return func() (interface{}, error) {
		v := os.Getenv(k)
		return v, nil
	}
}

func providerConfigure(d *schema.ResourceData) (interface{}, error) {
	config := vinyldns.ClientConfiguration{
		AccessKey: d.Get("access_key").(string),
		SecretKey: d.Get("secret_key").(string),
		Host:      d.Get("host").(string),
		UserAgent: GetUserAgent(),
	}

	clientCertPath := d.Get("client_cert").(string)
	if clientCertPath != "" {
		cert, err := tls.LoadX509KeyPair(clientCertPath, clientCertPath)
		if err != nil {
			return nil, err
		}

		caCertPool := x509.NewCertPool()
		caCert, err := os.ReadFile(clientCertPath)
		if err != nil {
			return nil, err
		}
		caCertPool.AppendCertsFromPEM(caCert)

		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      caCertPool,
		}

		transport := &http.Transport{TLSClientConfig: tlsConfig}
		httpClient := &http.Client{Transport: transport}

		config.HTTPClient = httpClient
	}

	return vinyldns.NewClient(config), nil
}
