package com.example.xxe;

import java.io.StringReader;
import javax.xml.XMLConstants;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

public class CommentsCache {
  // Shared helper reached from several endpoints. The protections are only applied when
  // `securityEnabled` is true, and `ACCESS_EXTERNAL_DTD`/`ACCESS_EXTERNAL_SCHEMA` alone are not
  // treated as hardening, so the parser is unsafe.
  protected XMLStreamReader parseXml(String xml, boolean securityEnabled)
      throws XMLStreamException {
    XMLInputFactory xif = XMLInputFactory.newInstance();
    if (securityEnabled) {
      xif.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
      xif.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
    }
    return xif.createXMLStreamReader(new StringReader(xml)); // $ Alert
  }

  // Safe counterpart: DTDs and external entities are disabled.
  protected XMLStreamReader parseXmlHardened(String xml) throws XMLStreamException {
    XMLInputFactory xif = XMLInputFactory.newInstance();
    xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
    xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
    return xif.createXMLStreamReader(new StringReader(xml));
  }
}
