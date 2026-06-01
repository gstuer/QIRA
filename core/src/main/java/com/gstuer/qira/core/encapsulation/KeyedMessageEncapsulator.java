package com.gstuer.qira.core.encapsulation;

import com.gstuer.qira.core.message.Message;

import java.io.Serial;
import java.io.Serializable;
import java.security.Key;

public abstract class KeyedMessageEncapsulator<S extends Key, V extends Key> implements Serializable {
    @Serial
    private static final long serialVersionUID = -3464245090269317756L;

    private S encapsulationKey;
    private V decapsulationKey;

    public Message<?> encapsulate(Message<?> message) throws EncapsulationException {
        return this.getEncapsulationTransformation().apply(message, this.encapsulationKey);
    }

    public Message<?> decapsulate(Message<?> message) throws EncapsulationException {
        return this.getDecapsulationTransformation().apply(message, this.decapsulationKey);
    }

    protected S getEncapsulationKey() {
        return this.encapsulationKey;
    }

    public void setEncapsulationKey(S encapsulationKey) {
        this.encapsulationKey = encapsulationKey;
    }

    protected V getDecapsulationKey() {
        return this.decapsulationKey;
    }

    public void setDecapsulationKey(V decapsulationKey) {
        this.decapsulationKey = decapsulationKey;
    }

    protected abstract KeyedTransformation<Message<?>, Message<?>, S> getEncapsulationTransformation();

    protected abstract KeyedTransformation<Message<?>, Message<?>, V> getDecapsulationTransformation();

    public interface KeyedTransformation<T, R, K> {
        R apply(T value, K key) throws EncapsulationException;
    }
}
