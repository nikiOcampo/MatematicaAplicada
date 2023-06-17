package com.example.rabbit.service;

import com.example.rabbit.domain.RabbitRequest;
import org.springframework.stereotype.Service;

import java.io.IOException;

@Service
public class ImageService {

    public void encryptImage(String path, RabbitRequest request) throws IOException {
        RabbitCipher.cryptByPythonFile(path, request);
    }

}
