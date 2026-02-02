package com.nageoffer.shortlink.project.mq.producer;

import com.alibaba.fastjson2.JSON;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Slf4j
@Component
@RequiredArgsConstructor
public class ShortLinkStatsSaveProducer {

    private final RabbitTemplate rabbitTemplate;

    @Value("${rabbitmq.exchange.stats-save:short-link.stats.exchange}")
    private String statsSaveExchange;

    @Value("${rabbitmq.routing-key.stats-save:short-link.stats.routing-key}")
    private String statsSaveRoutingKey;

    public void send(Map<String, String> producerMap) {
        String keys = UUID.randomUUID().toString();
        producerMap.put("keys", keys);
        try {
            // 直接发送，RabbitMQ 会根据 Exchange 和 RoutingKey 投递
            rabbitTemplate.convertAndSend(statsSaveExchange, statsSaveRoutingKey, producerMap);
            log.info("[消息访问统计监控] 消息发送成功，消息Keys：{}", keys);
        } catch (Throwable ex) {
            log.error("[消息访问统计监控] 消息发送失败，消息体：{}", JSON.toJSONString(producerMap), ex);
        }
    }
}