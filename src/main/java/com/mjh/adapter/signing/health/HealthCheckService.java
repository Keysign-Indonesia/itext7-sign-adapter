package com.mjh.adapter.signing.health;

//import io.swagger.annotations.Api;
//import io.swagger.annotations.ApiOperation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController("myhealthservices")
@RequestMapping({"/healthcheck"})
//@Api(value = "Server Health Check", description = "Operations to check server health")
public class HealthCheckService {
    Logger logger = LoggerFactory.getLogger(HealthCheckService.class);

    static final long thresholdDefault = 95L;

    static long maxMemory = Runtime.getRuntime().maxMemory();

    static long totalMemory = Runtime.getRuntime().totalMemory();

    static long freeMemory = Runtime.getRuntime().freeMemory();

    static long usedMemory = totalMemory - freeMemory;

    static long percentageMemory = usedMemory / maxMemory * 100L;

    @GetMapping({"/serverhealth"})
//    @ApiOperation(value = "Check server health", response = String.class)
    public String index() {
        return "ALLOK - {maxMemory|totalMemory|freeMemory|usedMemory|percentageMemory} : " + maxMemory + "|" + totalMemory + "|" + freeMemory + "|" + usedMemory + "|" + percentageMemory;
    }

    @GetMapping({"/readiness"})
//    @ApiOperation(value = "Check server readiness health", response = String.class)
    public ResponseEntity<String> readiness() {
        return new ResponseEntity("ALLOK", HttpStatus.OK);
    }

    @GetMapping({"/liveness"})
//    @ApiOperation(value = "Check server liveness health", response = String.class)
    public ResponseEntity<String> liveness() {
        if (calculateMemory(95L)) {
            this.logger.debug("STATMEM :" + percentageMemory);
            return new ResponseEntity("KO", HttpStatus.NOT_FOUND);
        }
        this.logger.debug("STATMEM :" + percentageMemory);
        return new ResponseEntity("ALLOK", HttpStatus.OK);
    }

    @GetMapping({"/liveness/{threshold}"})
//    @ApiOperation(value = "Check server liveness health", response = String.class)
    public ResponseEntity<String> livenessWithParam(@PathVariable long threshold) {
        if (threshold < 60L)
            threshold = 95L;
        if (calculateMemory(threshold)) {
            this.logger.debug("STATMEM :" + percentageMemory);
            return new ResponseEntity("KO", HttpStatus.NOT_FOUND);
        }
        this.logger.debug("STATMEM :" + percentageMemory);
        return new ResponseEntity("ALLOK", HttpStatus.OK);
    }

    private boolean calculateMemory(long threshold) {
        maxMemory = Runtime.getRuntime().maxMemory();
        totalMemory = Runtime.getRuntime().totalMemory();
        freeMemory = Runtime.getRuntime().freeMemory();
        usedMemory = totalMemory - freeMemory;
        percentageMemory = usedMemory / maxMemory * 100L;
        return (percentageMemory > threshold);
    }
}
