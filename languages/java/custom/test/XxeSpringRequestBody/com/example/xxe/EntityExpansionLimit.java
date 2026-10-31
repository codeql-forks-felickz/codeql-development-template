package com.example.xxe;

import java.io.StringReader;
import javax.xml.parsers.SAXParserFactory;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.xml.sax.InputSource;
import org.xml.sax.XMLReader;

@RestController
public class EntityExpansionLimit {
  @PostMapping(path = "/xxe/entity-expansion-unbounded")
  @ResponseBody
  public void parseUnbounded(@RequestBody String xml) throws Exception { // $ Source
    XMLReader reader = SAXParserFactory.newInstance().newSAXParser().getXMLReader();
    reader.setProperty("http://www.oracle.com/xml/jaxp/properties/entityExpansionLimit", 0);
    reader.parse(new InputSource(new StringReader(xml))); // $ Alert
  }

  @PostMapping(path = "/xxe/entity-expansion-safe")
  @ResponseBody
  public void parseSafe(@RequestBody String xml) throws Exception {
    XMLReader reader = SAXParserFactory.newInstance().newSAXParser().getXMLReader();
    reader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    reader.parse(new InputSource(new StringReader(xml)));
  }
}
