package bootstrap

import (
	"github.com/evalops/service-runtime/observability"
	"github.com/prometheus/client_golang/prometheus"
	goredis "github.com/redis/go-redis/v9"
)

func instrumentDefaultRedisClient(client goredis.UniversalClient) error {
	return instrumentRedisClient(client, prometheus.DefaultRegisterer)
}

func instrumentRedisClient(client goredis.UniversalClient, registerer prometheus.Registerer) error {
	if client == nil {
		return nil
	}
	hook, err := observability.NewRedisCommandHook("asb", observability.RedisCommandMetricsOptions{
		Registerer: registerer,
	})
	if err != nil {
		return err
	}
	client.AddHook(hook)
	return nil
}
