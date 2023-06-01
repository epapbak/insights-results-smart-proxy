// Copyright 2023 Red Hat, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package services contains interface implementations to other
// services that are called from Smart Proxy.
package services

import (
	"context"
	"errors"
	"time"

	redisV9 "github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"
)

const (
	redisExecutionFailedMsg = "unexpected response from Redis server"
)

// RedisInterface represents interface for functions executed against a Redis server
type RedisInterface interface {
	HealthCheck() error
}

// RedisClient is an implementation of the Redis client for Redis server
type RedisClient struct {
	Client *redisV9.Client
}

// explicit checks for config params are done because the go-redis package lets us create a client
// with incorrect params, so errors are only found during subsequent command executions
func createRedisClient(conf RedisConfiguration) (*redisV9.Client, error) {
	if conf.RedisEndpoint == "" {
		err := errors.New("Redis server address must not be empty")
		log.Error().Err(err)
		return nil, err
	}

	if conf.RedisDatabase < 0 || conf.RedisDatabase > 15 {
		err := errors.New("Redis selected database must be a value in the range 0-15")
		log.Error().Err(err)
		return nil, err
	}

	log.Info().Msgf("creating redis client. endpoint %v, selected DB %d, timeout seconds %d",
		conf.RedisEndpoint, conf.RedisDatabase, conf.RedisTimeoutSeconds,
	)

	// DB is configurable in case we want to change data structure
	c := redisV9.NewClient(&redisV9.Options{
		Addr:        conf.RedisEndpoint,
		DB:          conf.RedisDatabase,
		Password:    conf.RedisPassword,
		ReadTimeout: time.Duration(conf.RedisTimeoutSeconds) * time.Second,
	})

	return c, nil
}

// NewRedisClient creates a new Redis client based on configuration and returns RedisInterface
func NewRedisClient(conf RedisConfiguration) (RedisInterface, error) {
	client, err := createRedisClient(conf)
	if err != nil {
		return nil, err
	}

	return &RedisClient{
		Client: client,
	}, nil
}

// HealthCheck executes PING command to check for liveness status of Redis server
func (redis *RedisClient) HealthCheck() (err error) {
	ctx := context.Background()

	// .Result() gets value and error of executed command at once
	res, err := redis.Client.Ping(ctx).Result()
	if err != nil || res != "PONG" {
		log.Error().Err(err).Msg("Redis PING command failed")
		return errors.New(redisExecutionFailedMsg)
	}

	return
}