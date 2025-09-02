use vpn_libs_endpoint::rules::{Rule, RuleAction, RulesConfig};
use crate::user_interaction::{ask_for_agreement, ask_for_input};
use crate::get_mode;

pub fn build() -> RulesConfig {
    match get_mode() {
        crate::Mode::NonInteractive => build_non_interactive(),
        crate::Mode::Interactive => build_interactive(),
    }
}

fn build_non_interactive() -> RulesConfig {
    // In non-interactive mode, generate empty rules
    // The actual examples will be in the serialized TOML comments
    RulesConfig { rule: vec![] }
}

fn build_interactive() -> RulesConfig {
    println!("Setting up connection filtering rules...");
    
    let mut rules = Vec::new();
    
    // Ask if user wants to configure rules
    if !ask_for_agreement("Do you want to configure connection filtering rules? (if not, all connections will be allowed)") {
        println!("Skipping rules configuration - all connections will be allowed.");
        return RulesConfig { rule: vec![] };
    }
    
    println!();
    println!("You can configure rules to allow/deny connections based on:");
    println!("  - Client IP address (CIDR notation, e.g., 192.168.1.0/24)");
    println!("  - TLS client random prefix (hex-encoded, e.g., aabbcc)");
    println!("  - Both conditions together");
    println!();

    add_custom_rules(&mut rules);
    
    RulesConfig { rule: rules }
}

fn add_custom_rules(rules: &mut Vec<Rule>) {
    println!();
    while ask_for_agreement("Add a custom rule?") {
        let rule_type = ask_for_input::<String>(
            "Rule type (1=IP range, 2=client random prefix, 3=both)",
            Some("1".to_string()),
        );
        
        match rule_type.as_str() {
            "1" => add_ip_rule(rules),
            "2" => add_client_random_rule(rules),
            "3" => add_combined_rule(rules),
            _ => {
                println!("Invalid choice. Skipping rule.");
                continue;
            }
        }
        println!();
    }
}

fn add_ip_rule(rules: &mut Vec<Rule>) {
    let cidr = ask_for_input::<String>(
        "Enter IP range in CIDR notation (e.g., 203.0.113.0/24)",
        None,
    );
    
    // Validate CIDR format
    if let Err(_) = cidr.parse::<ipnet::IpNet>() {
        println!("Invalid CIDR format. Skipping rule.");
        return;
    }
    
    let action = ask_for_rule_action();
    
    rules.push(Rule {
        cidr: Some(cidr),
        client_random_prefix: None,
        action,
    });
    
    println!("Rule added successfully.");
}

fn add_client_random_rule(rules: &mut Vec<Rule>) {
    let prefix = ask_for_input::<String>(
        "Enter client random prefix (hex, e.g., aabbcc)",
        None,
    );
    
    // Validate hex format
    if let Err(_) = hex::decode(&prefix) {
        println!("Invalid hex format. Skipping rule.");
        return;
    }
    
    let action = ask_for_rule_action();
    
    rules.push(Rule {
        cidr: None,
        client_random_prefix: Some(prefix),
        action,
    });
    
    println!("Rule added successfully.");
}

fn add_combined_rule(rules: &mut Vec<Rule>) {
    let cidr = ask_for_input::<String>(
        "Enter IP range in CIDR notation (e.g., 172.16.0.0/12)",
        None,
    );
    
    // Validate CIDR format
    if let Err(_) = cidr.parse::<ipnet::IpNet>() {
        println!("Invalid CIDR format. Skipping rule.");
        return;
    }
    
    let prefix = ask_for_input::<String>(
        "Enter client random prefix (hex, e.g., 001122)",
        None,
    );
    
    // Validate hex format
    if let Err(_) = hex::decode(&prefix) {
        println!("Invalid hex format. Skipping rule.");
        return;
    }
    
    let action = ask_for_rule_action();
    
    rules.push(Rule {
        cidr: Some(cidr),
        client_random_prefix: Some(prefix),
        action,
    });
    
    println!("Rule added successfully.");
}

fn ask_for_rule_action() -> RuleAction {
    let action_str = ask_for_input::<String>(
        "Action (allow/deny)",
        Some("allow".to_string()),
    );
    
    match action_str.to_lowercase().as_str() {
        "deny" => RuleAction::Deny,
        _ => RuleAction::Allow,
    }
}
