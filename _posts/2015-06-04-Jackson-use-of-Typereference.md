---
layout: post
---
Jackson is a defacto standard to use JSON to POJO or vice-versa.  Org.json was used for some time before and that had alot of problems. It was an interesting problem to use dynamic type reference to convert a json string to map to Pojo. Finally, We end up with using some functions lik the one pasted below.

    package com.ksgbabu.client;

    import org.codehaus.jackson.map.ObjectMapper;
    import org.codehaus.jackson.type.TypeReference;
    import org.junit.Test;

    public class Mapper {

       @Test
       public void testSendAndReceive() throws Exception {
           MisMessageDto dto = new MisMessageDto();
           dto.setSvar("hello");
           dto.setVar(new MyIntern("myBonect"));
           TypeReference<MisMessageDto<MyIntern>> typeReference = new TypeReference<MisMessageDto<MyIntern>> () {};
           MisMessageDto<MyIntern> rdto = sendAndReceive(dto, typeReference);
           System.out.println(rdto.getSvar());
           System.out.println(((MyIntern)rdto.getVar()).getInternString());
       }

       public <T> T sendAndReceive(MisMessageDto dto,TypeReference<T> reference) throws  Exception{
           ObjectMapper mapper = new ObjectMapper();
           String json = mapper.writeValueAsString(dto);
           System.out.println(json);

           T response =  mapper.readValue(json, reference);
           return  response;
       }

    }
 
 