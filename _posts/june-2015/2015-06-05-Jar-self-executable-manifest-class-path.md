---
layout: post
---
It was tiresome to understand how do we setup a class path ('Class-Path') in manifest file to create a self executable jar file.  To make it work with gradle finally I had to use the full path names to the jarfile in the Class-Path attribute as:

    apply plugin: 'java'
    
    buildscript {
	     repositories {
	         maven {
	             url "https://plugins.gradle.org/m2/"
	         }
	     }
	 }

	 sourceCompatibility = 1.6
	 version = '1.0'

	 repositories {
	     mavenCentral()
	 }

	 dependencies {
	     testCompile group: 'junit', name: 'junit', version: '4.11'
	     compile 'org.eclipse.jetty:jetty-client:8.1.17.v20150415'
	     compile 'org.codehaus.jackson:jackson-jaxrs:1.9.13'

	 }

	 jar {
	     manifest {
	         attributes 'Main-Class': 'com.ksgbabu.client.Main'
	         if (!configurations.runtime.isEmpty()) {
	             attributes('Class-Path':
	                     configurations.compile.collect{it.toURI().toString()}.join(' '))
	         }
	     }
	     from("$projectDir") {
	         include 'lib/**'
	     }
	 }