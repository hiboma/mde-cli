use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndicatorType {
    FileSha256,
    FileSha1,
    FileMd5,
    CertificateThumbprint,
    IpAddress,
    DomainName,
    Url,
}

impl IndicatorType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::FileSha256 => "FileSha256",
            Self::FileSha1 => "FileSha1",
            Self::FileMd5 => "FileMd5",
            Self::CertificateThumbprint => "CertificateThumbprint",
            Self::IpAddress => "IpAddress",
            Self::DomainName => "DomainName",
            Self::Url => "Url",
        }
    }

    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.to_lowercase().replace(['-', '_'], "").as_str() {
            "filesha256" => Some(Self::FileSha256),
            "filesha1" => Some(Self::FileSha1),
            "filemd5" => Some(Self::FileMd5),
            "certificatethumbprint" => Some(Self::CertificateThumbprint),
            "ipaddress" | "ip" => Some(Self::IpAddress),
            "domainname" | "domain" => Some(Self::DomainName),
            "url" => Some(Self::Url),
            _ => None,
        }
    }
}

impl fmt::Display for IndicatorType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndicatorAction {
    Allowed,
    Alert,
    AlertAndBlock,
    Block,
}

impl IndicatorAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allowed => "Allowed",
            Self::Alert => "Alert",
            Self::AlertAndBlock => "AlertAndBlock",
            Self::Block => "Block",
        }
    }

    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.to_lowercase().replace(['-', '_'], "").as_str() {
            "allowed" | "allow" => Some(Self::Allowed),
            "alert" => Some(Self::Alert),
            "alertandblock" => Some(Self::AlertAndBlock),
            "block" => Some(Self::Block),
            _ => None,
        }
    }
}

impl fmt::Display for IndicatorAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_indicator_type_from_str() {
        assert_eq!(
            IndicatorType::from_str_loose("FileSha256"),
            Some(IndicatorType::FileSha256)
        );
        assert_eq!(
            IndicatorType::from_str_loose("filesha256"),
            Some(IndicatorType::FileSha256)
        );
        assert_eq!(
            IndicatorType::from_str_loose("ip"),
            Some(IndicatorType::IpAddress)
        );
        assert_eq!(
            IndicatorType::from_str_loose("domain"),
            Some(IndicatorType::DomainName)
        );
        assert_eq!(IndicatorType::from_str_loose("unknown"), None);
    }

    #[test]
    fn test_indicator_action_from_str() {
        assert_eq!(
            IndicatorAction::from_str_loose("Allowed"),
            Some(IndicatorAction::Allowed)
        );
        assert_eq!(
            IndicatorAction::from_str_loose("allow"),
            Some(IndicatorAction::Allowed)
        );
        assert_eq!(
            IndicatorAction::from_str_loose("AlertAndBlock"),
            Some(IndicatorAction::AlertAndBlock)
        );
        assert_eq!(IndicatorAction::from_str_loose("unknown"), None);
    }
}
