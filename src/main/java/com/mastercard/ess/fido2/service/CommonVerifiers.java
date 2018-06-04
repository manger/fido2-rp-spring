/*
 * Copyright (c) 2018 Mastercard
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and limitations under the License.
 */

package com.mastercard.ess.fido2.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

@Service
class CommonVerifiers {
    private static final Logger LOGGER = LoggerFactory.getLogger(CommonVerifiers.class);
    private static final byte U2F_USER_PRESENTED = 0x01;

    @Autowired
    @Qualifier("base64UrlDecoder")
    private Base64.Decoder base64UrlDecoder;

    @Autowired
    @Qualifier("base64UrlEncoder")
    private Base64.Encoder base64UrlEncoder;

    @Autowired
    @Qualifier("base64Decoder")
    private Base64.Decoder base64Decoder;

    @Autowired
    @Qualifier("cborMapper")
    ObjectMapper cborMapper;


    void verifyAttestationSignature(AuthData authData, byte[] clientDataHash, String signature, X509Certificate certificate) {
        int bufferSize = 0;
        byte[] reserved = new byte[]{0x00};
        bufferSize += reserved.length;
        byte[] rpIdHash = authData.getRpIdHash();
        bufferSize += rpIdHash.length;

        bufferSize += clientDataHash.length;
        byte[] credId = authData.getCredId();
        bufferSize += credId.length;
        byte[] publicKey = convertCOSEtoPublicKey(authData.getCOSEPublicKey());
        bufferSize += publicKey.length;

        byte[] signatureBase = ByteBuffer.allocate(bufferSize).put(reserved).put(rpIdHash).put(clientDataHash).put(credId).put(publicKey).array();
        byte[] signatureBytes = base64Decoder.decode(signature.getBytes());
        LOGGER.info("Signature {}", Hex.encodeHexString(signatureBytes));
        LOGGER.info("Signature Base {}", Hex.encodeHexString(signatureBase));
        verifySignature(signatureBytes, signatureBase, certificate);
    }

    void verifyAssertionSignature(AuthData authData, byte[] clientDataHash, String signature, ECPublicKey publicKey) {
        int bufferSize = 0;
        byte[] rpIdHash = authData.getRpIdHash();
        bufferSize += rpIdHash.length;
        byte[] flags= authData.getFlags();
        bufferSize += flags.length;
        byte[] counters= authData.getCounters();
        bufferSize += counters.length;
        bufferSize += clientDataHash.length;
        LOGGER.info("Client data hash HEX {}", Hex.encodeHexString(clientDataHash));
        byte[] signatureBase = ByteBuffer.allocate(bufferSize).put(rpIdHash).put(flags).put(counters).put(clientDataHash).array();
        byte[] signatureBytes = base64UrlDecoder.decode(signature.getBytes());
        LOGGER.info("Signature {}", Hex.encodeHexString(signatureBytes));
        LOGGER.info("Signature Base {}", Hex.encodeHexString(signatureBase));
        verifySignature(signatureBytes, signatureBase, publicKey);
    }

    boolean verifyUserPresent(AuthData authData) {
        if ((authData.getFlags()[0] & U2F_USER_PRESENTED) == 1) {
            return true;
        } else {
            throw new RuntimeException("User not present");
        }
    }

    void verifyRpIdHash(AuthData authData, String domain) {
        try {
            byte[] retrievedRpIdHash = authData.getRpIdHash();
            byte[] calculatedRpIdHash = DigestUtils.getSha256Digest().digest(domain.getBytes("UTF-8"));
            LOGGER.debug("rpIDHash from Domain    HEX {}", Hex.encodeHexString(calculatedRpIdHash));
            LOGGER.debug("rpIDHash from Assertion HEX {}", Hex.encodeHexString(retrievedRpIdHash));
            if (!Arrays.equals(retrievedRpIdHash, calculatedRpIdHash)) {
                LOGGER.warn("hash from domain doesn't match hash from assertion HEX ");
                throw new RuntimeException("Hashes don't match");
            }
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    void verifyCounter(int counter, int oldCounter) {
        if(oldCounter < counter) {
            throw new RuntimeException("Counter did not increase");
        }

    }

    private byte[] convertCOSEtoPublicKey(byte[] cosePublicKey) {
        try {
            JsonNode cborPublicKey = cborMapper.readTree(cosePublicKey);
            byte[] x = base64Decoder.decode(cborPublicKey.get("-2").asText());
            byte[] y = base64Decoder.decode(cborPublicKey.get("-3").asText());
            byte[] keyBytes = ByteBuffer.allocate(1 + x.length + y.length).put((byte) 0x04).put(x).put(y).array();
            LOGGER.info("KeyBytes HEX {}", Hex.encodeHexString(keyBytes));
            return keyBytes;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void verifySignature(byte[] signature, byte[] signatureBase, X509Certificate certificate) {
        verifySignature(signature, signatureBase,certificate.getPublicKey());
    }

    private void verifySignature(byte[] signature, byte[] signatureBase, PublicKey publicKey) {
        try {
            Signature signatureChecker = Signature.getInstance("SHA256withECDSA");
            signatureChecker.initVerify(publicKey);
            signatureChecker.update(signatureBase);
            if (!signatureChecker.verify(signature)) {
                throw new RuntimeException("Unable to verify signature");
            }

        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new RuntimeException(e);
        }
    }
}
