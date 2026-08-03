package io.github.ersincivi.passwordless.push;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.listener.ChannelTopic;
import org.springframework.stereotype.Service;

@Service
public class PushService {

    private final RedisTemplate<String, Object> template;
    private final ChannelTopic topic;

    public PushService(RedisTemplate<String, Object> template, ChannelTopic pushTopic) {
        this.template = template;
        this.topic = pushTopic;
    }

    public void publish(PushMessage message) {
        template.convertAndSend(topic.getTopic(), message);
    }
}


