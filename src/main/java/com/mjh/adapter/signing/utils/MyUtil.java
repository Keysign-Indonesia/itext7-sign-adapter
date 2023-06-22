package com.mjh.adapter.signing.utils;

import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MyUtil {
    private static final Logger logger = LoggerFactory.getLogger(com.mjh.adapter.signing.utils.MyUtil.class);

    public static String base64encode(byte[] value) {
        return new String(Base64.encodeBase64(value));
    }

    public static byte[] base64decode(String value) {
        return Base64.decodeBase64(value);
    }

}
