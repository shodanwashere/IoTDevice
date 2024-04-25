echo ">>> Building IoTDevice"
if ls target > /dev/null ; then
	printf "[+] Detected existing target folder. Cleaning up..."
	mvn clean > /dev/null
	printf " Done!\n"
fi
printf "[+] Compiling... "
mvn compile > /dev/null
printf "Done!\n[+] Packaging... "
mvn package > /dev/null
printf "Done!\n"
if ls iotdevice-1.0.jar > /dev/null; then
	printf "[+] Old sample executable detected. Cleaning up..."
	rm iotdevice-1.0.jar > /dev/null
	printf " Done!\n"
fi
printf "[+] Obtaining new sample executable for server... "
cp target/iotdevice-1.0.jar . > /dev/null
printf "Done!\n"
echo ">>> Build complete! You can find the executables on the 'target' directory."
