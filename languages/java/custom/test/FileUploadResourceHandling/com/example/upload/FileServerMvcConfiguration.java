package com.example.upload;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/** Publishes the file server directory as static web content under `/files/**`. */
public class FileServerMvcConfiguration implements WebMvcConfigurer {
  @Value("${fileserver.location}")
  private String fileLocation;

  @Override
  public void addResourceHandlers(ResourceHandlerRegistry registry) {
    registry.addResourceHandler("/files/**").addResourceLocations("file:///" + fileLocation + "/");
  }
}
