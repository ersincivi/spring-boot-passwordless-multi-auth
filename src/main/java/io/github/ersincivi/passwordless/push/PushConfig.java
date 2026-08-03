package io.github.ersincivi.passwordless.push;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.MessageListener;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.listener.ChannelTopic;
import org.springframework.data.redis.listener.RedisMessageListenerContainer;
import org.springframework.data.redis.listener.adapter.MessageListenerAdapter;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;

@Configuration
public class PushConfig {

    public static final String TOPIC = "passwordless:push:global";

    @Bean
    public ChannelTopic pushTopic() {
        return new ChannelTopic(TOPIC);
    }

    // T6.3: publishing uses the shared RedisTemplate<String, Object> bean from
    // RedisConfig (identical String-key + JSON-value serializers).

    @Bean
    public MessageListenerAdapter pushListenerAdapter(PushSubscriber subscriber) {
        MessageListenerAdapter adapter = new MessageListenerAdapter(subscriber, "receive");
        adapter.setSerializer(new GenericJackson2JsonRedisSerializer());
        return adapter;
    }

    @Bean
    public RedisMessageListenerContainer pushListenerContainer(RedisConnectionFactory connectionFactory,
                                                              MessageListener pushListenerAdapter,
                                                              ChannelTopic pushTopic) {
        RedisMessageListenerContainer container = new RedisMessageListenerContainer();
        container.setConnectionFactory(connectionFactory);
        container.addMessageListener(pushListenerAdapter, pushTopic);
        return container;
    }
}


