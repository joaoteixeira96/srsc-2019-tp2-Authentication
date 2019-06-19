FROM openjdk:8
WORKDIR /usr/src/myapp
COPY /src /usr/src/myapp/
COPY  servertls.conf ciphersuite.properties authentication authentication.cert authentication.jks authenticationTruststore.jks /usr/src/myapp/
RUN javac ./server/Authentication/AuthenticationServer.java
CMD ["java","server.Authentication.AuthenticationServer"]