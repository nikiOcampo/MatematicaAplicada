package com.example.rabbit.controllers;

import com.example.rabbit.domain.Option;
import com.example.rabbit.domain.RabbitRequest;
import com.example.rabbit.service.ImageService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

import javax.validation.Valid;
import java.io.File;
import java.io.IOException;

@Controller
public class ImageController {

    private final ImageService imageService;
    private static final Logger LOGGER = LoggerFactory.getLogger(ImageController.class);

    @Value("${config.uploads.path}")
    private String path;

    @Autowired
    public ImageController(ImageService imageService) {
        this.imageService = imageService;
    }

    @GetMapping({"/", "/home"})
    public String home(Model model) {
        model.addAttribute("rabbitRequest", new RabbitRequest());
        model.addAttribute("title", "Cifrador de Flujo Rabbit");
        return "home";
    }

    @PostMapping(value = "/form", consumes = {"*/*"})
    public String save(
        @Valid RabbitRequest request,
        BindingResult result,
        @RequestParam MultipartFile file
    ) throws IOException {
        String fileName = file.getOriginalFilename();
        if (!result.hasErrors() && fileName != null && !fileName.isEmpty()) {
            //Save the file in a tmp folder
            String name = (Option.E.equals(request.getOption())) ? "imageToEncrypt" : "imageToDecrypt";
            String extension = fileName.substring(fileName.indexOf("."));
            request.setPicture(name.concat(extension));
            file.transferTo(new File(path + request.getPicture()));

            try {
                imageService.encryptImage(path, request);
                LOGGER.info("{} successfully", request.getOption().getValue());
            } catch (Exception e) {
                LOGGER.error("Error encrypted/decrypted image", e);
            }
            return "redirect:/home?success=" + request.getOption().getValue() + " correctamente";
        }

        return "redirect:/home?error=Errores en el formulario, por favor complete todos los campos";
    }

}
