---
layout: post
---

I was looking at some project with maven assebly configurations.  I thought just note it down for future reference.  To create a configuration assembly first add a module and mention that module name in the parent pom.  Say the module name can be Configuraiton.  Within the pom of that module mention as:

	<?xml version="1.0"?>
	<project xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd" xmlns="http://maven.apache.org/POM/4.0.0"
	    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
	  <modelVersion>4.0.0</modelVersion>
	  <parent>
	    <groupId>package</groupId>
	    <artifactId>mine</artifactId>
	    <version>1.0-SNAPSHOT</version>
	  </parent>
	  <groupId>group-id</groupId>
	  <artifactId>configuration</artifactId>
	  <packaging>pom</packaging>
	  <version>1.0-SNAPSHOT</version>
	  <name>MIS::Configuration</name>
	  <properties>
	    <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
	    <work.dir>${project.build.directory}/${project.build.finalName}</work.dir>
	  </properties>
	  <build>
	      <finalName>${project.artifactId}</finalName>
	      <resources>
	          <resource>
	              <directory>src/main/resources</directory>
	              <filtering>true</filtering>
	          </resource>
	      </resources>
	      <plugins>
	          <plugin>
	              <groupId>org.apache.maven.plugins</groupId>
	              <artifactId>maven-resources-plugin</artifactId>
	              <executions>
	                  <execution>
	                      <id>local</id>
	                      <phase>process-resources</phase>
	                      <goals>
	                          <goal>resources</goal>
	                      </goals>
	                      <configuration>
	                          <encoding>UTF-8</encoding>
	                          <outputDirectory>${work.dir}/local</outputDirectory>
	                          <filters>
	                              <filter>${basedir}/src/main/filters/local.properties</filter>
	                          </filters>
	                      </configuration>
	                  </execution>
	                  <execution>
	                      <id>dist</id>
	                      <phase>process-resources</phase>
	                      <goals>
	                          <goal>resources</goal>
	                      </goals>
	                      <configuration>
	                          <encoding>UTF-8</encoding>
	                          <outputDirectory>${work.dir}/dist</outputDirectory>
	                          <filters>
	                              <filter>${basedir}/src/main/filters/dist.properties</filter>
	                          </filters>
	                      </configuration>
	                  </execution>
	              </executions>
	          </plugin>
	          <plugin>
	              <groupId>org.apache.maven.plugins</groupId>
	              <artifactId>maven-assembly-plugin</artifactId>
	              <configuration>
	                  <descriptors>
	                      <descriptor>assembly/dist.xml</descriptor>
	                  </descriptors>
	              </configuration>
	              <executions>
	                  <execution>
	                      <id>make-assemblies</id>
	                      <phase>package</phase>
	                      <goals>
	                          <goal>single</goal>
	                      </goals>
	                  </execution>
	              </executions>
	          </plugin>
	      </plugins>
	  </build>
	</project>
    

Create a folder structure:

	assembly
		dist.xml
	src
		main
			filters
				dist.properties
				local.properties
			resources
				jetty
					jetty.xml
				my.properties
				
other files:

dist.xml

	<assembly xmlns="http://maven.apache.org/plugins/maven-assembly-plugin/assembly/1.1.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
	          xsi:schemaLocation="http://maven.apache.org/plugins/maven-assembly-plugin/assembly/1.1.0 http://maven.apache.org/xsd/assembly-1.1.0.xsd">
	    <id>dist</id>
	    <baseDirectory>/</baseDirectory>
	    <formats>
	        <format>zip</format>
	    </formats>
	    <fileSets>
	        <fileSet>
	            <directory>${work.dir}/dist</directory>
	            <outputDirectory>/</outputDirectory>
	            <includes>
	                <include>my.properties</include>
	            </includes>
	        </fileSet>
	    </fileSets>
	</assembly>
	

jetty.xml

	<?xml version="1.0" encoding="UTF-8"?>
	<!DOCTYPE Configure PUBLIC "-//Mort Bay Consulting//DTD Configure//EN" "http://jetty.mortbay.org/configure.dtd">
	<Configure class="org.eclipse.jetty.server.Server">

	    <New id="myConfigLocation" class="org.eclipse.jetty.plus.jndi.EnvEntry">
	        <Arg></Arg>
	        <Arg>mis/config</Arg>
	        <Arg type="java.lang.String">${mis.config.path}/my.properties</Arg>
	        <Arg type="boolean">false</Arg>
	    </New>

	</Configure>
	

####Similary the Assembly can also be used for distribution zip

We can have a folder structure like:
	
	dist
		assembly
			assembly.xml
	pom.xml
	

assembly.xml

<assembly xmlns="http://maven.apache.org/plugins/maven-assembly-plugin/assembly/1.1.2"
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
          xsi:schemaLocation="http://maven.apache.org/plugins/maven-assembly-plugin/assembly/1.1.2 http://maven.apache.org/xsd/assembly-1.1.2.xsd">

    <id>dist</id>

    <formats>
        <format>zip</format>
    </formats>

    <files>
        <!-- My server EAR-->
        <file>
            <source>${mis.ear.dir}/target/my.ear</source>
            <outputDirectory>/ear</outputDirectory>
        </file>
        <!-- My server WAR-->
        <file>
            <source>${my.web.dir}/target/my-web.war</source>
            <outputDirectory>/wars</outputDirectory>
        </file>

        <!-- Adapters -->
        <file>
            <source>${my.adapters.dir}/adapters-common/target/my-adapters-common.jar</source>
            <outputDirectory>/resource-adapters</outputDirectory>
        </file>
    </files>
</assembly>

pom.xml

	<?xml version="1.0"?>
	<project xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd" xmlns="http://maven.apache.org/POM/4.0.0"
	    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
	  <modelVersion>4.0.0</modelVersion>
	  <parent>
	    <groupId>group</groupId>
	    <artifactId>artefact</artifactId>
	    <version>1.0-SNAPSHOT</version>
	  </parent>
	  <groupId>group</groupId>
	  <artifactId>dist</artifactId>
	  <packaging>pom</packaging>
	  <version>1.0-SNAPSHOT</version>
	  <name>MIS::Distribution</name>
	  <properties>
	    <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
	  </properties>
	  <dependencies>
	      <dependency>
	          <groupId>group-package</groupId>
	          <artifactId>ear</artifactId>
	          <version>1.0-SNAPSHOT</version>
	          <type>ear</type>
	      </dependency>
	  </dependencies>
	    <build>
	        <finalName>my</finalName>

	        <plugins>
	            <plugin>
	                <groupId>org.codehaus.mojo</groupId>
	                <artifactId>build-helper-maven-plugin</artifactId>
	                <executions>
	                    <execution>
	                        <id>attach-distribution</id>
	                        <phase>package</phase>
	                        <goals>
	                            <goal>attach-artifact</goal>
	                        </goals>
	                        <configuration>
	                            <artifacts>
	                                <artifact>
	                                    <file>${project.build.directory}/mis-dist.zip</file>
	                                    <type>zip</type>
	                                </artifact>
	                            </artifacts>
	                        </configuration>
	                    </execution>
	                </executions>
	            </plugin>
	            <plugin>
	                <groupId>org.apache.maven.plugins</groupId>
	                <artifactId>maven-assembly-plugin</artifactId>
	                <configuration>
	                    <descriptors>
	                        <descriptor>${project.basedir}/assembly/assembly.xml</descriptor>
	                    </descriptors>
	                    <outputDirectory>${project.build.directory}</outputDirectory>
	                    <workDirectory>${work.dir}</workDirectory>
	                </configuration>
	                <executions>
	                    <execution>
	                        <id>make-assembly</id> <!-- this is used for inheritance merges -->
	                        <phase>package</phase>  <!-- bind to the packaging phase -->
	                        <goals>
	                            <goal>single</goal>
	                        </goals>
	                    </execution>
	                </executions>
	            </plugin>
	        </plugins>
	    </build>

	</project>
	