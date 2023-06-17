package com.example.rabbit.domain;

import lombok.Getter;

@Getter
public enum Option {
    E("Encriptado"),
    D("Desencriptado");

    private final String value;

    Option(String value) {
        this.value = value;
    }

	public String getValue() {
		return value;
	}
    
    

}
