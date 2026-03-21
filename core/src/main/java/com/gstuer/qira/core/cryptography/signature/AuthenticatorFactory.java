package com.gstuer.qira.core.cryptography.signature;

import com.gstuer.qira.core.cryptography.signature.algorithm.AES256GMAC;
import com.gstuer.qira.core.cryptography.signature.algorithm.HmacSHA256;
import com.gstuer.qira.core.cryptography.signature.algorithm.MLDSA44;
import com.gstuer.qira.core.cryptography.signature.algorithm.MLDSA65;
import com.gstuer.qira.core.cryptography.signature.algorithm.MLDSA87;

import java.util.Optional;

public final class AuthenticatorFactory {
    private AuthenticatorFactory() {
    }

    public static Optional<Authenticator<?, ?>> createByIdentifier(String algorithmIdentifier) {
        Authenticator<?, ?> authenticator = switch (algorithmIdentifier) {
            case AES256GMAC.ALGORITHM_IDENTIFIER -> new AES256GMAC();
            case HmacSHA256.ALGORITHM_IDENTIFIER -> new HmacSHA256();
            case MLDSA44.ALGORITHM_IDENTIFIER -> new MLDSA44();
            case MLDSA65.ALGORITHM_IDENTIFIER -> new MLDSA65();
            case MLDSA87.ALGORITHM_IDENTIFIER -> new MLDSA87();
            default -> null;
        };
        return Optional.ofNullable(authenticator);
    }
}
