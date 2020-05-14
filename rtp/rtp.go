package rtp

import (
	"context"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/uuid"
	"github.com/pion/rtp"
	"gitlab.com/permtr.com/check-service/storage"
	"strconv"
	"time"
)

// Сниффер RTP пакетов
type RTP struct {
	Storage StorageRTP
}

// RTP пакет
type rtpPacket struct {
	// Порт назначения
	DstPort        uint16
	// Порт источника
	SrcPort        uint16
	// IP назначения
	DstIp          string
	// IP источника
	SrcIp          string
	// 16-ти разрядный счётчик, увеличивающийся с каждым отправленным пакетом
	SequenceNumber uint16
	// Временная метка, для h.264 величина дискрета составляет 1/90000 c (т.е. соответствует частоте 90 КГц)
	Timestamp      uint32
	// Этим битом чаще всего камеры маркируют начало видео-кадра и специализированные пакеты с SPS/PPS-информацией
	Marker         bool
	// Имеет особое значение тогда, когда с одного IP вещается несколько потоков, т.е. в случае с многопортовым энкодером
	SSRC           uint32
}

// Запускаем анализ трафика
func (r *RTP) Start(device string) error {
	if handle, err := pcap.OpenLive(device, 1600, true, pcap.BlockForever); err != nil {
		return err
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		// Смотрим все пакеты
		for packet := range packetSource.Packets() {
			// Сетевой уровень
			tcp := packet.Layer(layers.LayerTypeTCP)
			// Сетевой уровень
			udp := packet.Layer(layers.LayerTypeUDP)
			// Транспортный уровень
			ipv4l := packet.Layer(layers.LayerTypeIPv4)
			// Транспортный уровень
			ipv6l := packet.Layer(layers.LayerTypeIPv6)
			var ipv4 *layers.IPv4
			var ipv6 *layers.IPv6
			if ipv4l != nil {
				ipv4 = ipv4l.(*layers.IPv4)
			}

			if ipv6l != nil {
				ipv6 = ipv6l.(*layers.IPv6)
			}

			if tcp != nil {
				// Обрабатываем TCP пакет
				err := r.handleLayer(tcp, ipv4, ipv6)
				if err != nil {
					return err
				}
			} else if udp != nil {
				// Обрабатываем UDP пакет
				err := r.handleLayer(udp, ipv4, ipv6)
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// Обработчик пакета
func (r *RTP) handleLayer(layer gopacket.Layer, ipv4 *layers.IPv4, ipv6 *layers.IPv6) error {

	// RTP пакет по спецификации
	p := &rtp.Packet{}
	if err := p.Unmarshal([]byte{}); err == nil {
		fmt.Println(err)
	}

	// Анмаршалим
	if err := p.Unmarshal(layer.LayerPayload()); err != nil {
		fmt.Println(err)
	}

	// Эмпирически найденные значение, которые покрывают 100% rtp пакетов всех камер
	if p.Version == 2 && p.PayloadType >= 96 && p.PayloadType <= 100 {
		rtpp := &rtpPacket{}

		// Достаем данные из траспортного уровня
		err := rtpp.UnmarshalTransport(layer)
		if err != nil {
			return err
		}

		// Достаем данные из сетевого уровня
		err = rtpp.UnmarshalNetwork(ipv4, ipv6)
		if err != nil {
			return err
		}

		// Данные из RTP пакета
		rtpp.SequenceNumber = p.SequenceNumber
		rtpp.Timestamp = p.Timestamp
		rtpp.Marker = p.Marker
		rtpp.SSRC = p.SSRC

		// Формируем структуру для сохранения
		pack := storage.RtpPacket{
			Id:             uuid.New().String(),
			DstPort:        rtpp.DstPort,
			SrcPort:        rtpp.SrcPort,
			DstIp:          rtpp.DstIp,
			SrcIp:          rtpp.SrcIp,
			SequenceNumber: rtpp.SequenceNumber,
			Timestamp:      rtpp.Timestamp,
			Marker:         rtpp.Marker,
			Ssrc:           rtpp.SSRC,
			StandardTime: storage.StandardTime{
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			},
		}

		// Сохраняем для анализа
		err = r.Storage.CreateRtpPacket(context.Background(), pack)
		if err != nil {
			return err
		}
	}
	return nil
}

// Данные сетевого уровня
func (r *rtpPacket) UnmarshalNetwork(ipv4 *layers.IPv4, ipv6 *layers.IPv6) error {
	if ipv4 != nil {
		r.SrcIp = ipv4.SrcIP.String()
		r.DstIp = ipv4.DstIP.String()
	}

	if ipv6 != nil {
		r.SrcIp = ipv6.SrcIP.String()
		r.DstIp = ipv6.DstIP.String()
	}
	return nil
}

// Данные траспортного уровня
func (r *rtpPacket) UnmarshalTransport(layer gopacket.Layer) error {
	var udp *layers.UDP
	var isUDP bool
	tcp, isTCP := layer.(*layers.TCP)
	if !isTCP {
		udp, isUDP = layer.(*layers.UDP)
		if !isUDP {
			return nil
		}
	}
	if tcp != nil {
		port, err := strconv.Atoi(tcp.DstPort.String())
		if err != nil {
			return err
		}
		r.DstPort = uint16(port)
		port, err = strconv.Atoi(tcp.SrcPort.String())
		if err != nil {
			return err
		}
		r.SrcPort = uint16(port)
	} else if udp != nil {
		port, err := strconv.Atoi(udp.DstPort.String())
		if err != nil {
			return err
		}
		r.DstPort = uint16(port)
		port, err = strconv.Atoi(udp.SrcPort.String())
		if err != nil {
			return err
		}
		r.SrcPort = uint16(port)
	} else {
		return nil
	}

	return nil
}