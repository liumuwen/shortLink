package com.nageoffer.shortlink.project.config;

import org.springframework.amqp.support.converter.Jackson2JsonMessageConverter;
import org.springframework.amqp.support.converter.MessageConverter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class RabbitConfig {

    @Bean
    public MessageConverter messageConverter() {
        // 使用 Jackson 自动处理 Map 和 DTO 的 JSON 转换
        return new Jackson2JsonMessageConverter();
    }
}