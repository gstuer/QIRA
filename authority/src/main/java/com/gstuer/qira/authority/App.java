package com.gstuer.qira.authority;

import com.google.common.io.Files;
import com.gstuer.qira.core.cryptography.signature.Authenticator;
import com.gstuer.qira.core.cryptography.signature.algorithm.MLDSA87;
import com.gstuer.qira.core.egress.DatagramEgressHandler;
import com.gstuer.qira.core.ingress.DatagramIngressHandler;
import com.gstuer.qira.core.message.Message;
import com.gstuer.qira.core.serialization.JsonProcessor;
import com.gstuer.qira.core.serialization.SerializationException;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import java.io.File;
import java.io.IOException;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;

public class App {
    private static final int UDP_PORT_INCOMING = 10000;
    private static final int UDP_PORT_OUTGOING = 10001;

    public static void main(String[] args) {
        System.out.println("IA - Identity Authority");

        // Configure SLF4J logging verbosity
        System.setProperty("slf4j.internal.verbosity", "WARN");
        System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "WARN");

        // Parse command line arguments without required options to avoid help dialog not being printed in case of missing arguments
        CommandLine commandLine;
        try {
            commandLine = parseCommandLine(args, false);
        } catch (ParseException exception) {
            System.err.println(exception.getMessage());
            return;
        }

        // Print help dialog if requested by user
        if (commandLine.hasOption("h")) {
            displayHelp();
            return;
        }

        // Parse command line arguments with required options
        try {
            commandLine = parseCommandLine(args, true);
        } catch (ParseException exception) {
            System.err.println(exception.getMessage());
            return;
        }

        // Generate or read authenticator
        Authenticator<?, ?> authenticator;
        File authenticatorFile = new File("./authenticator_ia.json");
        File verifierFile = new File("./verifier_ia.json");
        JsonProcessor jsonProcessor = new JsonProcessor();
        if (commandLine.hasOption("g")) {
            authenticator = new MLDSA87();
            authenticator.initializeKeyPair();

            // Write authenticator and verifier to file
            try {
                Files.asCharSink(authenticatorFile, JsonProcessor.getDefaultCharset()).write(jsonProcessor.convertToJson(authenticator));
                Files.asCharSink(verifierFile, JsonProcessor.getDefaultCharset()).write(jsonProcessor.convertToJson(authenticator.getShareableVerifier()));
            } catch (IOException | SerializationException exception) {
                throw new IllegalStateException(exception);
            }
        } else {
            try {
                String jsonAuthenticator = Files.asCharSource(authenticatorFile, JsonProcessor.getDefaultCharset()).read();
                authenticator = jsonProcessor.convertToObject(jsonAuthenticator, Authenticator.class);
            } catch (IOException | SerializationException exception) {
                System.err.println("[IA] Authenticator file not readable. Please re-run with -g option to generate new authenticator.");
                return;
            }
        }

        // Construct controller
        BlockingQueue<Message<?>> egressQueue = new LinkedBlockingQueue<>();
        BindingMessageHandler messageHandler = new BindingMessageHandler(egressQueue, authenticator);

        // Construct ingress and egress handlers
        DatagramEgressHandler egressHandler = new DatagramEgressHandler(UDP_PORT_OUTGOING, UDP_PORT_INCOMING, egressQueue);
        DatagramIngressHandler ingressHandler = new DatagramIngressHandler(UDP_PORT_INCOMING, messageHandler::handleRequest);

        // Start handler threads
        ExecutorService threadPool = Executors.newFixedThreadPool(2);
        threadPool.submit(egressHandler::open);
        threadPool.submit(ingressHandler::open);
    }

    private static CommandLine parseCommandLine(String[] args, boolean parseWithRequiredOptions) throws ParseException {
        CommandLineParser parser = new DefaultParser(false);
        return parser.parse(getCommandLineOptions(parseWithRequiredOptions), args, false);
    }

    private static void displayHelp() {
        HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp("app", getCommandLineOptions(true), true);
    }

    private static Options getCommandLineOptions(boolean enableRequiredOptions) {
        Options options = new Options();
        options.addOption(Option.builder("g")
                .longOpt("generate")
                .desc("generates key material for the digital signature algorithm")
                .build());
        options.addOption(Option.builder("h")
                .longOpt("help")
                .desc("displays usage information of the program and exit")
                .build());
        return options;
    }
}
