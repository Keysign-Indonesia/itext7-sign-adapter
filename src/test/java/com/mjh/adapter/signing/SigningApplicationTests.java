package com.mjh.adapter.signing;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import java.security.Security;

@SpringBootTest
class SigningApplicationTests {

	@BeforeAll
	public static void setUpBeforeClass() throws Exception {
		Security.addProvider(new BouncyCastleProvider());
	}

	@Test
	void contextLoads() {
	}

}
