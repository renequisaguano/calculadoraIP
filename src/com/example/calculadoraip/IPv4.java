package com.example.calculadoraip;



import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class IPv4 {
	int baseIPnumeric;
	int netmaskNumeric;

	/**
	 * Especifique la dirección IP y máscara de red como:
	 * IPv4("10.1.0.25","255.255.255.16")
	 * 
	 * @param symbolicIP
	 * @param netmask
	 */
	public IPv4(String symbolicIP, String netmask) throws NumberFormatException {
		/* IP */
		String[] st = symbolicIP.split("\\.");
		if (st.length != 4)
			throw new NumberFormatException("Direccion IP Invalida: " + symbolicIP);

		int i = 24;
		baseIPnumeric = 0;
		for (int n = 0; n < st.length; n++) {
			int value = Integer.parseInt(st[n]);
			if (value != (value & 0xff)) {
				throw new NumberFormatException("Direccion IP Invalida: "
						+ symbolicIP);
			}

			baseIPnumeric += value << i;
			i -= 8;
		}

		/* Netmask */
		st = netmask.split("\\.");
		if (st.length != 4)
			throw new NumberFormatException("Mascara de Subred Invalida: "
					+ netmask);

		i = 24;
		netmaskNumeric = 0;
		if (Integer.parseInt(st[0]) < 255) {
			throw new NumberFormatException(
					"El primer bit de la netmask no puede ser menor que 255");
		}
		for (int n = 0; n < st.length; n++) {
			int value = Integer.parseInt(st[n]);
			if (value != (value & 0xff)) {
				throw new NumberFormatException("Mascara de Subred Invalida: "
						+ netmask);
			}

			netmaskNumeric += value << i;
			i -= 8;
		}

		boolean encounteredOne = false;
		int ourMaskBitPattern = 1;
		for (i = 0; i < 32; i++) {
			if ((netmaskNumeric & ourMaskBitPattern) != 0) {
				encounteredOne = true; // the bit is 1
			} else { // the bit is 0
				if (encounteredOne == true)
					throw new NumberFormatException("Mascara de Subred Invalida: "
							+ netmask + " (bit " + (i + 1) + ")");
			}

			ourMaskBitPattern = ourMaskBitPattern << 1;
		}

	}

	/**
	 *  IP en formato CIDR ejemplo: new IPv4("10.1.0.25/16");
	 * 
	 * @param IPinCIDRFormat
	 */
	public IPv4(String IPinCIDRFormat) throws NumberFormatException {
		String[] st = IPinCIDRFormat.split("\\/");
		if (st.length != 2)
			throw new NumberFormatException("Formato CIDR invalido '"
					+ IPinCIDRFormat + "', deberia ser: xx.xx.xx.xx/xx");
		String symbolicIP = st[0];
		String symbolicCIDR = st[1];
		Integer numericCIDR = new Integer(symbolicCIDR);
		if (numericCIDR > 32)
			throw new NumberFormatException("CIDR no puede ser mayor que 32");

		/* IP */
		st = symbolicIP.split("\\.");
		if (st.length != 4)
			throw new NumberFormatException("Direccion IP invalida: " + symbolicIP);

		int i = 24;
		baseIPnumeric = 0;
		for (int n = 0; n < st.length; n++) {
			int value = Integer.parseInt(st[n]);
			if (value != (value & 0xff)) {
				throw new NumberFormatException("Direccion IP invalida: "
						+ symbolicIP);
			}

			baseIPnumeric += value << i;
			i -= 8;
		}

		/* netmask from CIDR */
		if (numericCIDR < 8)
			throw new NumberFormatException(
					"CIDR no puede ser menor que 8");
		netmaskNumeric = 0xffffffff;
		netmaskNumeric = netmaskNumeric << (32 - numericCIDR);
	}

	/**
	 * Get the IP in symbolic form, i.e. xxx.xxx.xxx.xxx
	 * 
	 * @return
	 */
	public String getIP() {
		return convertNumericIpToSymbolic(baseIPnumeric);
	}

	private String convertNumericIpToSymbolic(Integer ip) {
		StringBuffer sb = new StringBuffer(15);
		for (int shift = 24; shift > 0; shift -= 8) {
			// process 3 bytes, from high order byte down.
			sb.append(Integer.toString((ip >>> shift) & 0xff));
			sb.append('.');
		}
		sb.append(Integer.toString(ip & 0xff));
		return sb.toString();
	}

	/**
	 * Obtener mascara en forma simbolica i.e. xxx.xxx.xxx.xxx
	 * 
	 * @return
	 */
	public String getNetmask() {
		StringBuffer sb = new StringBuffer(15);
		for (int shift = 24; shift > 0; shift -= 8) {
			// process 3 bytes, from high order byte down.
			sb.append(Integer.toString((netmaskNumeric >>> shift) & 0xff));
			sb.append('.');
		}
		sb.append(Integer.toString(netmaskNumeric & 0xff));
		return sb.toString();
	}

	/**
	 * Obtener ip and netmask en formato CIDR , i.e. xxx.xxx.xxx.xxx/xx
	 * 
	 * @return
	 */

	public String getCIDR() {
		int i;
		for (i = 0; i < 32; i++) {
			if ((netmaskNumeric << i) == 0)
				break;
		}
		return convertNumericIpToSymbolic(baseIPnumeric & netmaskNumeric) + "/"
				+ i;
	}


	public List<String> getAvailableIPs(Integer numberofIPs) {
		ArrayList<String> result = new ArrayList<String>();
		int numberOfBits;
		for (numberOfBits = 0; numberOfBits < 32; numberOfBits++) {
			if ((netmaskNumeric << numberOfBits) == 0)
				break;
		}
		Integer numberOfIPs = 0;
		for (int n = 0; n < (32 - numberOfBits); n++) {
			numberOfIPs = numberOfIPs << 1;
			numberOfIPs = numberOfIPs | 0x01;
		}

		Integer baseIP = baseIPnumeric & netmaskNumeric;

		for (int i = 1; i < (numberOfIPs) && i < numberofIPs; i++) {
			Integer ourIP = baseIP + i;

			String ip = convertNumericIpToSymbolic(ourIP);
			result.add(ip);
		}

		return result;

	}

	/**
	 * Rango de Hosts
	 * 
	 * @return
	 */
	public String getHostAddressRange() {
		int numberOfBits;
		for (numberOfBits = 0; numberOfBits < 32; numberOfBits++) {
			if ((netmaskNumeric << numberOfBits) == 0)
				break;
		}
		Integer numberOfIPs = 0;
		for (int n = 0; n < (32 - numberOfBits); n++) {
			numberOfIPs = numberOfIPs << 1;
			numberOfIPs = numberOfIPs | 0x01;
		}

		Integer baseIP = baseIPnumeric & netmaskNumeric;
		String firstIP = convertNumericIpToSymbolic(baseIP + 1);
		String lastIP = convertNumericIpToSymbolic(baseIP + numberOfIPs - 1);

		return firstIP + " - " + lastIP;
	}

	/**
	 * Numero de Host
	 * 
	 * @return number of hosts
	 */
	public Long getNumberOfHosts() {
		int numberOfBits;
		for (numberOfBits = 0; numberOfBits < 32; numberOfBits++) {
			if ((netmaskNumeric << numberOfBits) == 0)
				break;
		}

		Double x = Math.pow(2, (32 - numberOfBits));
		if (x == -1)
			x = 1D;
		return x.longValue();
	}

	/**
	 * WildCard
	 * 
	 * @return wildcard mask in text form, i.e. 0.0.15.255
	 */
	public String getWildcardMask() {
		Integer wildcardMask = netmaskNumeric ^ 0xffffffff;
		StringBuffer sb = new StringBuffer(15);
		for (int shift = 24; shift > 0; shift -= 8) {
			// process 3 bytes, from high order byte down.
			sb.append(Integer.toString((wildcardMask >>> shift) & 0xff));
			sb.append('.');
		}
		sb.append(Integer.toString(wildcardMask & 0xff));
		return sb.toString();

	}

	public String getBroadcastAddress() {
		if (netmaskNumeric == 0xffffffff)
			return "0.0.0.0";

		int numberOfBits;
		for (numberOfBits = 0; numberOfBits < 32; numberOfBits++) {
			if ((netmaskNumeric << numberOfBits) == 0)
				break;
		}
		Integer numberOfIPs = 0;
		for (int n = 0; n < (32 - numberOfBits); n++) {
			numberOfIPs = numberOfIPs << 1;
			numberOfIPs = numberOfIPs | 0x01;
		}

		Integer baseIP = baseIPnumeric & netmaskNumeric;
		Integer ourIP = baseIP + numberOfIPs;
		String ip = convertNumericIpToSymbolic(ourIP);

		return ip;
	}

	private String getBinary(Integer number) {
		String result = "";
		Integer ourMaskBitPattern = 1;
		for (int i = 1; i <= 32; i++) {
			if ((number & ourMaskBitPattern) != 0) {
				result = "1" + result; // the bit is 1
			} else { // the bit is 0
				result = "0" + result;
			}
			if ((i % 8) == 0 && i != 0 && i != 32)
				result = "." + result;
			ourMaskBitPattern = ourMaskBitPattern << 1;
		}
		return result;
	}

	public String getNetmaskInBinary() {
		return getBinary(netmaskNumeric);
	}


	public boolean contains(String IPaddress) {
		Integer checkingIP = 0;
		String[] st = IPaddress.split("\\.");
		if (st.length != 4)
			throw new NumberFormatException("Direccion IP invalida: " + IPaddress);

		int i = 24;
		for (int n = 0; n < st.length; n++) {
			int value = Integer.parseInt(st[n]);
			if (value != (value & 0xff)) {
				throw new NumberFormatException("Direccion IP invalida: "
						+ IPaddress);
			}

			checkingIP += value << i;
			i -= 8;
		}

		if ((baseIPnumeric & netmaskNumeric) == (checkingIP & netmaskNumeric))
			return true;
		else
			return false;
	}

	public boolean contains(IPv4 child) {

		Integer subnetID = child.baseIPnumeric;
		Integer subnetMask = child.netmaskNumeric;

		if ((subnetID & this.netmaskNumeric) == (this.baseIPnumeric & this.netmaskNumeric)) {
			if ((this.netmaskNumeric < subnetMask) == true
					&& this.baseIPnumeric <= subnetID) {
				return true;
			}

		}
		return false;
	}

	public boolean validateIPAddress() {
		String IPAddress = getIP();
		if (IPAddress.startsWith("0")) {
			return false;
		}

		if (IPAddress.isEmpty()) {
			return false;
		}

		if (IPAddress
				.matches("\\A(25[0-5]|2[0-4]\\d|[0-1]?\\d?\\d)(\\.(25[0-5]|2[0-4]\\d|[0-1]?\\d?\\d)){3}\\z")) {
			return true;
		}
		return false;
	}


	
    private String getBoundaryAddr(boolean lowBoundary){
        String result = "";
        String range = getHostAddressRange();
        Pattern rangeRegex = Pattern.compile("(\\d+\\.\\d+\\.\\d+\\.\\d+)\\s+\\-\\s+(\\d+\\.\\d+\\.\\d+\\.\\d+)");
        Matcher m = rangeRegex.matcher(range);
        if( m.matches() ){
            if( lowBoundary ){
                result = m.group(1);
            } else {
                result = m.group(2);
            }
        }
        return result;
    }

    public String getFirstIPAddr(){
        return getBoundaryAddr(true);
    }

    public String getLastIPAddr(){
        return getBoundaryAddr(false);
    }
	

	public static void main(String[] args) {
		// ipv4.setIP("10.20.30.5", "255.255.255.200");
		// System.out.println(ipv4.getIP());
		// System.out.println(ipv4.getNetmask());
		// System.out.println(ipv4.getCIDR());

		/*
		 * IPv4 ipv4 = new IPv4("10.1.17.0/20");
		 * System.out.println(ipv4.getIP());
		 * System.out.println(ipv4.getNetmask());
		 * System.out.println(ipv4.getCIDR());
		 * 
		 * System.out.println("============= Available IPs ===============");
		 * List<String> availableIPs = ipv4.getAvailableIPs(); int counter=0;
		 * for (String ip : availableIPs) { System.out.print(ip);
		 * System.out.print(" "); counter++; if((counter%10)==0)
		 * System.out.print("\n"); }
		 */

		IPv4 ipv4 = new IPv4("12.12.12.0/16");
		IPv4 ipv4Child = new IPv4("12.12.12.0/17");
		// IPv4 ipv4 = new IPv4("192.168.20.0/16");
		// System.out.println(ipv4.getIP());
		// System.out.println(ipv4.getNetmask());
		// System.out.println(ipv4.getCIDR());
		// System.out.println("======= MATCHES =======");
		// System.out.println(ipv4.getBinary(ipv4.baseIPnumeric));
		// System.out.println(ipv4.getBinary(ipv4.netmaskNumeric));

		System.out.println(ipv4.contains(ipv4Child));

		System.out.println(ipv4.getBinary(ipv4.baseIPnumeric));
		System.out.println(ipv4.getBinary(ipv4.netmaskNumeric));

		System.out.println(ipv4Child.getBinary(ipv4Child.baseIPnumeric));
		System.out.println(ipv4Child.getBinary(ipv4Child.netmaskNumeric));
		System.out.println("==============output================");
		System.out.println(ipv4.contains(ipv4Child));
		// ipv4.contains("192.168.50.11");
		// System.out.println("======= DOES NOT MATCH =======");
		// ipv4.contains("10.2.3.4");
		// System.out.println(ipv4.validateIPAddress());
		// System.out.println(ipv4.getBinary(ipv4.baseIPnumeric));
		// System.out.println(ipv4.getBinary(ipv4.netmaskNumeric));
	}

}
