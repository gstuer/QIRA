package com.gstuer.qira.core.encapsulation;

import com.gstuer.qira.core.message.Message;

import java.io.Serial;
import java.io.Serializable;
import java.security.Key;
import java.util.Objects;

public abstract class KeyedMessageEncapsulator<S extends Key, V extends Key> implements Serializable {
    @Serial
    private static final long serialVersionUID = -3464245090269317756L;

    private S encapsulationKey;
    private V decapsulationKey;

    public abstract Message<?> encapsulate(Message<?> message) throws EncapsulationException;

    public abstract Message<?> decapsulate(Message<?> message) throws EncapsulationException;

    @Override
    public boolean equals(Object object) {
        if (object == null || getClass() != object.getClass()) {
            return false;
        }
        KeyedMessageEncapsulator<?, ?> that = (KeyedMessageEncapsulator<?, ?>) object;
        return Objects.equals(this.getEncapsulationKey(), that.getEncapsulationKey())
                && Objects.equals(this.getDecapsulationKey(), that.getDecapsulationKey());
    }

    @Override
    public int hashCode() {
        return Objects.hash(this.getEncapsulationKey(), this.getDecapsulationKey());
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

    public interface KeyedTransformation<T, R, K> {
        R apply(T value, K key) throws EncapsulationException;
    }
}
