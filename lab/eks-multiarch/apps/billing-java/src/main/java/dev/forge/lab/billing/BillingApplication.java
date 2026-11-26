package dev.forge.lab.billing;

import java.net.InetAddress;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

// billing-java: small REST API. Logging the user agent with Log4j 2.14.1 is the
// classic Log4Shell call path; forge must block this image before it ships.
@SpringBootApplication
@RestController
public class BillingApplication {

    private static final Logger log = LogManager.getLogger(BillingApplication.class);

    record Invoice(long id, String customer, double amount) {}

    private final Map<Long, Invoice> invoices = new ConcurrentHashMap<>();
    private final AtomicLong seq = new AtomicLong();

    public static void main(String[] args) {
        SpringApplication.run(BillingApplication.class, args);
    }

    @GetMapping("/healthz")
    public String health() {
        return "ok";
    }

    @GetMapping("/info")
    public Map<String, String> info() throws Exception {
        return Map.of("app", "billing-java", "arch", System.getProperty("os.arch"),
                "java", System.getProperty("java.version"),
                "pod", InetAddress.getLocalHost().getHostName());
    }

    @GetMapping("/invoices")
    public List<Invoice> list(@RequestHeader(value = "User-Agent", defaultValue = "-") String ua) {
        log.info("list invoices, user agent: {}", ua);
        return List.copyOf(invoices.values());
    }

    @PostMapping("/invoices")
    @ResponseStatus(HttpStatus.CREATED)
    public Invoice create(@RequestBody Invoice in) {
        if (in.customer() == null || in.amount() < 0) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "customer and amount >= 0 required");
        }
        Invoice saved = new Invoice(seq.incrementAndGet(), in.customer(), in.amount());
        invoices.put(saved.id(), saved);
        return saved;
    }

    @GetMapping("/invoices/{id}")
    public Invoice get(@PathVariable long id) {
        Invoice inv = invoices.get(id);
        if (inv == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "invoice not found");
        }
        return inv;
    }
}
