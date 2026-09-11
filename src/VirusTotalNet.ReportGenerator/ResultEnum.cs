namespace VirusTotalNet.ReportGenerator;

public enum ResultEnum
{
    [System.Xml.Serialization.XmlEnum("Undetected")]
    Undetected = 0,

    [System.Xml.Serialization.XmlEnum("Detected")]
    Detected = 1
}