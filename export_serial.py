import serial
import time

# Configurações da porta serial
PORT = 'COM6'  # Modifique para a porta correta do seu Arduino (no Linux pode ser algo como '/dev/ttyUSB0')
BAUDRATE = 115200
FILENAME = "corrente_log.csv"

def main():
    try:
        # Conectar à porta serial
        ser = serial.Serial(PORT, BAUDRATE, timeout=1)
        time.sleep(2)  # Aguarda a conexão estabilizar

        # Abre um arquivo para salvar os dados
        with open(FILENAME, 'w') as file:
            # Escreve o cabeçalho do CSV
            file.write("Timestamp(ms),Corrente(mA)\n")

            print("Capturando dados... Pressione Ctrl+C para interromper.")

            while True:
                # Ler uma linha da porta serial
                line = ser.readline().decode('utf-8').strip()
                
                # Se a linha conter "Timestamp (ms)", processar
                if "Timestamp (ms)" in line:
                    # Extrair o timestamp e a corrente da linha
                    parts = line.split(", ")
                    if len(parts) >= 2:
                        timestamp_str = parts[0].split(": ")[1]
                        corrente_str = parts[1].split(": ")[1].replace(" mA", "")

                        # Salvar os valores no arquivo CSV
                        file.write(f"{timestamp_str},{corrente_str}\n")
                        file.flush()

                        # Exibir no console
                        print(f"{timestamp_str},{corrente_str}")

    except serial.SerialException as e:
        print(f"Erro ao acessar a porta serial: {e}")
    except KeyboardInterrupt:
        print("Captura interrompida pelo usuário.")
    finally:
        if ser.is_open:
            ser.close()
        print("Conexão serial fechada.")

if __name__ == "__main__":
    main()
