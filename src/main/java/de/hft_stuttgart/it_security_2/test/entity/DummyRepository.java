package de.hft_stuttgart.it_security_2.test.entity;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface DummyRepository extends JpaRepository<Dummy, UUID> {}
