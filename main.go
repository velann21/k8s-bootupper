package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)


var target = "./kubernetes"
var etcdtarget = "./etcd"
func GenerateCACertTemplate() *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			CommonName:"/CN=KUBERNETES-CA",
			Organization:  []string{"RC Company, INC."},
			Country:       []string{"NL"},
			Province:      []string{""},
			Locality:      []string{"Amsterdam"},
			StreetAddress: []string{"welnestreet"},
			PostalCode:    []string{"1096"},
		},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(3, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
}

func GenerateKey(bits int) (*rsa.PrivateKey, error) {
	caPrivKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	return caPrivKey, nil
}

func CreateSelfSignedCACert(ca *x509.Certificate, caPrivateKey *rsa.PrivateKey) ([]byte, error) {
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivateKey.PublicKey, caPrivateKey)
	if err != nil {
		return nil, err
	}
	return caBytes, nil
}

func CreateCompCertWithCASign(compCert *x509.Certificate, caCert *x509.Certificate, compCertPrivateKey *rsa.PrivateKey, caPrivateKey *rsa.PrivateKey) ([]byte, error) {
	caBytes, err := x509.CreateCertificate(rand.Reader, compCert, caCert, &compCertPrivateKey.PublicKey, caPrivateKey)
	if err != nil {
		return nil, err
	}
	return caBytes, nil
}

func EncodeCertPEMEncoded(certBytes []byte, compPrivateKey *rsa.PrivateKey) ([]byte, []byte) {
	caPEM := new(bytes.Buffer)
	_ = pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	caPrivKeyPEM := new(bytes.Buffer)
	_ = pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(compPrivateKey),
	})

	return caPEM.Bytes(), caPrivKeyPEM.Bytes()

}

func GenerateComponentCertsTemplate(commonName string, ip[] string) *x509.Certificate {
	firstHex,_ := strconv.Atoi(ip[0])
	secondHex,_ := strconv.Atoi(ip[1])
	thirdHex,_ := strconv.Atoi(ip[2])
	fourthHex,_ := strconv.Atoi(ip[3])

	return &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			CommonName:    "/CN=etcd",
			Organization:  []string{"RC Company, INC."},
			Country:       []string{"NL"},
			Province:      []string{""},
			Locality:      []string{"Amsterdam"},
			StreetAddress: []string{"welnestreet"},
			PostalCode:    []string{"1096"},
		},

		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv4(byte(firstHex),byte(secondHex),byte(thirdHex),byte(fourthHex))},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		Extensions: []pkix.Extension{
			pkix.Extension{
				Value: []byte{3},
			},
		},
	}
}

func SignCertWithCA(compCert *x509.Certificate, caCert *x509.Certificate, compCertPrivateKey *rsa.PrivateKey) ([]byte, error) {
	certBytes, err := x509.CreateCertificate(rand.Reader, compCert, caCert, &compCertPrivateKey.PublicKey, compCertPrivateKey)
	if err != nil {
		return nil, err
	}

	return certBytes, nil
}

func GetServerBinaries() (*http.Response, error) {
	response, err := http.Get("https://dl.k8s.io/v1.18.0/kubernetes-server-linux-amd64.tar.gz")
	if err != nil {
		return nil, err
	}
	return response, nil
}

func GetEtcdBinaries() (*http.Response, error) {
	response, err := http.Get("https://github.com/etcd-io/etcd/releases/download/v3.4.13/etcd-v3.4.13-linux-amd64.tar.gz")
	if err != nil {
		return nil, err
	}
	return response, nil
}

func main() {


	ip := os.Args[1]

	caCert := GenerateCACertTemplate()
	caKey, err := GenerateKey(2048)
	if err != nil {
		log.Fatalln(err)
	}

	rootCACert, err := CreateSelfSignedCACert(caCert, caKey)
	if err != nil {
		log.Fatalln(err)
	}

	pemKey, privateKey := EncodeCertPEMEncoded(rootCACert, caKey)
	fmt.Println("PEM key", string(pemKey))
	fmt.Println("Private Key", string(privateKey))

	file, err := os.Create("./ca.crt")
	if err != nil {

		log.Fatalln(err)
	}
	_, _ = file.Write(pemKey)

	file2, err := os.Create("./ca.key")
	if err != nil {
		log.Fatalln(err)
	}
	_, _ = file2.Write(privateKey)

	ips := strings.Split(ip, ".")
	etcdCert := GenerateComponentCertsTemplate("localhost",ips)

	etcdKey, err := GenerateKey(2048)
	if err != nil {
		log.Fatalln(err)
	}

	etcdCertByte, err := CreateCompCertWithCASign(etcdCert,caCert, etcdKey, caKey)
	if err != nil {
		log.Fatalln(err)
	}

	etcdpemKey, etcdPrivateKey := EncodeCertPEMEncoded(etcdCertByte, etcdKey)

	etcdfile, err := os.Create("./etcd.crt")
	if err != nil {
		log.Fatalln(err)
	}
	_, _ = etcdfile.Write(etcdpemKey)

	etcdKeyFile, err := os.Create("./etcd.key")
	if err != nil {
		log.Fatalln(err)
	}
	_, _ = etcdKeyFile.Write(etcdPrivateKey)

	fmt.Println("DownloadK8sServerBinaries")
	DownloadK8sServerBinaries()
	fmt.Println("DownloadEtcdBinaries")
	DownloadEtcdBinaries()
	fmt.Println("CopyEtcdBinaryToUsrLcl")
	CopyEtcdBinaryToUsrLcl(ip)
	fmt.Println("ConfigureEtcd")
	ConfigureEtcd()
}

func CopyEtcdBinaryToUsrLcl(ips string){
	if runtime.GOOS == "windows" {
		fmt.Println("Can't Execute this on a windows machine")
	} else {
		fmt.Println("Executing ----->>>>>>>>>>>>>>>>>>>")
		moveEtcd(ips)
	}
}

func moveEtcd(ips string){
	localBin, err := exec.Command("cp", "-r","/home/singaravelannandakumar/etcd/etcd-v3.4.13-linux-amd64/etcd", "/usr/bin/").Output()
	if err != nil {
		log.Println("Error occured /usr/bin/")
		log.Fatal(err)
	}

	chnageEtcdPermission, err := exec.Command("chmod", "777", "/usr/bin/etcd").Output()
	if err != nil {
		log.Println("Error occured /usr/bin/etcd")
		log.Fatal(err)
	}


	local, err := exec.Command("cp", "-r","/home/singaravelannandakumar/etcd/etcd-v3.4.13-linux-amd64/etcd", "/usr/local/bin/").Output()
	if err != nil {
		log.Println("Error occured /usr/local/bin/")
		log.Fatal(err)
	}

	chnageEtcdPermissionBin, err := exec.Command("chmod", "777", "/usr/local/bin/etcd").Output()
	if err != nil {
		log.Println("Error occured /usr/bin/")
		log.Fatal(err)
	}


	etcdConf := GenerateEtcdConfFile(ips)

	fmt.Println("etcdConf______........", etcdConf)

	etcdService, err := exec.Command( "sh", "-c", etcdConf).Output()
	if err != nil {
		log.Println("Error occured cat")
		log.Fatal(err)
	}

	fmt.Println("chnageEtcdPermissionBin",string(chnageEtcdPermissionBin))
	fmt.Println("chnageEtcdPermission",string(chnageEtcdPermission))
	fmt.Println("localBin",string(localBin))
	fmt.Println("local",string(local))
	fmt.Println("etcdService",string(etcdService))


}


func GenerateEtcdConfFile(thisNodeIp string)string{

	conf := fmt.Sprintf(`cat <<EOF | sudo tee /etc/systemd/system/etcd.service
[Unit]
Description=etcd
Documentation=https://github.com/coreos
[Service]
ExecStart=/usr/local/bin/etcd \\
  --name master-1 \\
  --cert-file=/home/singaravelannandakumar/etcd.crt \\
  --key-file=/home/singaravelannandakumar/etcd.key \\
  --peer-cert-file=/home/singaravelannandakumar/etcd.crt \\
  --peer-key-file=/home/singaravelannandakumar/etcd.key \\
  --trusted-ca-file=/home/singaravelannandakumar/ca.crt \\
  --peer-trusted-ca-file=/home/singaravelannandakumar/ca.crt \\
  --peer-client-cert-auth \\
  --client-cert-auth \\
  --initial-advertise-peer-urls https://%s:2380 \\
  --listen-peer-urls https://%s:2380 \\
  --listen-client-urls https://%s:2379,https://127.0.0.1:2379 \\
  --advertise-client-urls https://%s:2379 \\
  --initial-cluster-token etcd-cluster-0 \\
  --initial-cluster master-1=https://%s:2380 \\
  --initial-cluster-state new \\
  --data-dir=/var/lib/etcd
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF`, thisNodeIp,thisNodeIp,thisNodeIp,thisNodeIp,thisNodeIp)

	return conf

}



func ConfigureEtcd(){
	systemCtlStart, err := exec.Command("sh", "-c",  "sudo systemctl start etcd").Output()
	if err != nil {
		log.Fatal("%s", err)
	}

	systemCtlStatus, err := exec.Command("sh", "-c", "sudo systemctl status etcd").Output()
	if err != nil {
		log.Fatal("%s", err)
	}
	systemCtlEnable, err := exec.Command("sh", "-c",  "sudo systemctl enable etcd").Output()
	if err != nil {
		log.Fatal("%s", err)
	}

	fmt.Println("systemCtlStart---->>>", string(systemCtlStart))
	fmt.Println("systemCtlStatus---->>>", string(systemCtlStatus))
    fmt.Println("systemCtlEnable--->>>", string(systemCtlEnable))
}

func DownloadEtcdBinaries(){
	resp, err := GetEtcdBinaries()
	if err != nil {
		log.Fatalln(err)
	}

	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		log.Fatalf("could not pull data from imdb, status code is %d", resp.StatusCode)
	}

	gReader, err := gzip.NewReader(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	if err := os.MkdirAll(etcdtarget, 0775); err != nil{
		log.Fatal(err)
	}

	tarReader := tar.NewReader(gReader)


	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}


		path := filepath.Join(etcdtarget, header.Name)
		switch header.Typeflag {
		case tar.TypeDir:
			_ = os.MkdirAll(path, header.FileInfo().Mode())
			continue


		case tar.TypeReg:
			fmt.Println("TypeReg")
			out, err := os.Create(path)
			if err != nil {
				log.Fatal(err)
			}
			_, _ = io.Copy(out, tarReader)



		default:
			fmt.Print("tar.default  ---------->>>>>>",)
			fmt.Println("Header", header)

		}

	}

}

func DownloadK8sServerBinaries(){
	resp, err := GetServerBinaries()
	if err != nil {
		log.Fatalln(err)
	}

	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		log.Fatalf("could not pull data from imdb, status code is %d", resp.StatusCode)
	}

	gReader, err := gzip.NewReader(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	if err := os.MkdirAll(target, 0755); err != nil{
		log.Fatal(err)
	}

	tarReader := tar.NewReader(gReader)


	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}


		path := filepath.Join(target, header.Name)
		switch header.Typeflag {
		case tar.TypeDir:
			_ = os.MkdirAll(path, header.FileInfo().Mode())
			continue


		case tar.TypeReg:
			fmt.Println("TypeReg")
			out, err := os.Create(path)
			if err != nil {
				log.Fatal(err)
			}
			_, _ = io.Copy(out, tarReader)



		default:
			fmt.Print("tar.default  ---------->>>>>>",)
			fmt.Println("Header", header)

		}

	}
}
