#!/usr/bin/env python

import argparse
import socket
import threading
import logging
import pandas as pd


def scan_port(ip_address, port):
    '''Check if port is open on host'''
    try:
        socket_obj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)
        result = socket_obj.connect_ex((ip_address, port))
        socket_obj.close()

        if result == 0:
            service = socket.getservbyport(port)
            return port, service

    except socket.error as e:
        logging.error(f"Error scanning port {port}: {str(e)}")

    return None


def banner_grabbing(ip_address, port):
    '''Connect to process and return application banner'''
    try:
        bannergrabber = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(2)
        bannergrabber.connect((ip_address, port))
        bannergrabber.send(b'WhoAreYou\r\n')
        banner = bannergrabber.recv(100)
        bannergrabber.close()
        return banner.strip()

    except socket.error as e:
        logging.error(f"Error grabbing banner for port {port}: {str(e)}")

    return None


def port_scan(ip_address, start_port, end_port):
    open_ports = []
    for port in range(start_port, end_port + 1):
        result = scan_port(ip_address, port)
        if result:
            open_ports.append(result)

    return open_ports


def get_service_banners(ip_address, open_ports):
    results = []
    for port, service in open_ports:
        banner = banner_grabbing(ip_address, port)
        if banner:
            results.append((ip_address, port, service, banner.decode()))
        else:
            results.append((ip_address, port, service, "Not available"))

    return results


def main():
    parser = argparse.ArgumentParser(description='Port Scanner')
    parser.add_argument('ip_address', type=str, help='Target IP address')
    parser.add_argument('start_port', type=int, help='Starting port')
    parser.add_argument('end_port', type=int, help='Ending port')

    args = parser.parse_args()

    ip_address = args.ip_address
    start_port = args.start_port
    end_port = args.end_port

    logging.basicConfig(filename='port_scan.log', level=logging.INFO, format='%(asctime)s - %(message)s')

    try:
        open_ports = port_scan(ip_address, start_port, end_port)
        results = get_service_banners(ip_address, open_ports)

        # Create a DataFrame from the results
        df = pd.DataFrame(results, columns=['IP Address', 'Port', 'Service', 'Banner'])

        # Save the DataFrame to an Excel file
        df.to_excel('port_scan_results.xlsx', index=False)

        logging.info(f"Port scan results saved to port_scan_results.xlsx")

    except Exception as e:
        logging.error(f"Error during port scanning: {str(e)}")


if __name__ == '__main__':
    main()
