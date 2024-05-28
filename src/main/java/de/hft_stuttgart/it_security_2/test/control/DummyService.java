package de.hft_stuttgart.it_security_2.test.control;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@Transactional
@RequiredArgsConstructor
class DummyService {

    public String getDummy() {
        return "dummy";
    }
}
