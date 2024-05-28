package de.hft_stuttgart.it_security_2.test.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import lombok.Data;

@Entity
@Data
public class Dummy {

    @Id
    private Integer id;

    private String lorem;

    private String ipsum;
}
