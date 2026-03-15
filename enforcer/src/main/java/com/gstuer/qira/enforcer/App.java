package com.gstuer.qira.enforcer;

import com.gstuer.qira.enforcer.forwarding.ForwardingBridge;
import com.gstuer.qira.enforcer.predicate.ArpPredicate;
import com.gstuer.qira.enforcer.predicate.IcmpV4Predicate;
import com.gstuer.qira.enforcer.predicate.LldpPredicate;
import com.gstuer.qira.enforcer.predicate.PrpPredicate;
import com.gstuer.qira.enforcer.predicate.PtpPredicate;
import com.gstuer.qira.enforcer.predicate.SshOverTcpPredicate;
import com.gstuer.qira.enforcer.predicate.StpPredicate;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.util.LinkLayerAddress;

import java.util.List;

public class App {
    public static void main(String[] args) {
        System.out.println("IP/CEP - Inline Cryptography Enforcement Point");

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

        // Print list of network interfaces if requested by user
        if (commandLine.hasOption("l")) {
            try {
                displayInterfaceList();
            } catch (PcapNativeException exception) {
                System.err.println("Listing network interfaces failed: " + exception.getMessage());
                return;
            }
        }

        // Parse command line arguments with required options
        try {
            commandLine = parseCommandLine(args, true);
        } catch (ParseException exception) {
            System.err.println(exception.getMessage());
            return;
        }

        // Parse interface identifiers from command line arguments and create pcap interfaces
        PcapNetworkInterface secureNetworkInterface;
        PcapNetworkInterface insecureNetworkInterface;
        String secureInterfaceIdentifier = commandLine.getOptionValue("s");
        String insecureInterfaceIdentifier = commandLine.getOptionValue("i");
        try {
            secureNetworkInterface = Pcaps.getDevByName(secureInterfaceIdentifier);
            insecureNetworkInterface = Pcaps.getDevByName(insecureInterfaceIdentifier);
        } catch (PcapNativeException exception) {
            System.err.println("Setting up interfaces failed: " + exception.getMessage());
            return;
        }

        // Parse authenticator from command line arguments
//        Optional<Authenticator<?, ?>> optionalAuthenticator = AuthenticatorFactory.createByIdentifier(commandLine.getOptionValue("crypto"));
//        if (optionalAuthenticator.isEmpty()) {
//            System.err.println("Parsing cryptographic algorithm failed: Unknown algorithm.");
//            return;
//        }
//        Authenticator<?, ?> authenticator = optionalAuthenticator.get();

        if (commandLine.hasOption("f")) {
            // Start forwarding traffic between the specified interfaces w/o supervision
            System.out.printf("Forward Mode: %s <-> %s\n", insecureNetworkInterface.getName(), secureNetworkInterface.getName());
            ForwardingBridge inBridge = new ForwardingBridge(insecureNetworkInterface, secureNetworkInterface);
            ForwardingBridge outBridge = new ForwardingBridge(secureNetworkInterface, insecureNetworkInterface);
            inBridge.startForwarding();
            outBridge.startForwarding();
        } else {
            // Start forwarding traffic between the specified interfaces using a secured network bridge instance
            System.out.printf("Supervisory Mode: %s <-> %s\n", insecureNetworkInterface.getName(), secureNetworkInterface.getName());
            NetworkBridge networkBridge = new NetworkBridge(insecureNetworkInterface, secureNetworkInterface,
                    new ArpPredicate(), new IcmpV4Predicate(), new LldpPredicate(), new PtpPredicate(),
                    new PrpPredicate(), new StpPredicate(), new SshOverTcpPredicate());
            networkBridge.open();
        }
    }

    private static void displayHelp() {
        HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp("app", getCommandLineOptions(true), true);
    }

    private static void displayInterfaceList() throws PcapNativeException {
        System.out.println("Available Network Interfaces:");
        List<PcapNetworkInterface> devices = Pcaps.findAllDevs();
        for (PcapNetworkInterface device : devices) {
            if (device.isUp() && !device.isLoopBack()) {
                LinkLayerAddress firstLinkLayerAddress = device.getLinkLayerAddresses().stream().findFirst().orElse(null);
                System.out.printf("    %s %s\n", device.getName(), firstLinkLayerAddress);
            }
        }
    }

    private static CommandLine parseCommandLine(String[] args, boolean parseWithRequiredOptions) throws ParseException {
        CommandLineParser parser = new DefaultParser(false);
        return parser.parse(getCommandLineOptions(parseWithRequiredOptions), args, false);
    }

    private static Options getCommandLineOptions(boolean enableRequiredOptions) {
        Options options = new Options();
        options.addOption(Option.builder("s")
                .longOpt("secure")
                .desc("set the secure interface of the program")
                .numberOfArgs(1)
                .argName("interface")
                .required(enableRequiredOptions)
                .build());
        options.addOption(Option.builder("i")
                .longOpt("insecure")
                .desc("set the insecure interface of the program")
                .numberOfArgs(1)
                .argName("interface")
                .required(enableRequiredOptions)
                .build());
//        options.addOption(Option.builder()
//                .longOpt("crypto")
//                .desc("set the cryptographic algorithm used for authentication")
//                .numberOfArgs(1)
//                .argName("algorithm")
//                .required(enableRequiredOptions)
//                .build());
        options.addOption(Option.builder("f")
                .longOpt("forward")
                .desc("forwards all traffic without filtering and supervision")
                .build());
        options.addOption(Option.builder("l")
                .longOpt("list")
                .desc("displays network interfaces usable as secure or insecure interface of the program")
                .build());
        options.addOption(Option.builder("h")
                .longOpt("help")
                .desc("displays usage information of the program and exit")
                .build());
        return options;
    }
}
