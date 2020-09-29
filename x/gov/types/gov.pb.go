// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: x/gov/gov.proto

package types

import (
	fmt "fmt"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	github_com_pokt_network_pocket_core_types "github.com/pokt-network/pocket-core/types"
	io "io"
	math "math"
	math_bits "math/bits"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion3 // please upgrade the proto package

type MsgChangeParam struct {
	FromAddress github_com_pokt_network_pocket_core_types.Address `protobuf:"bytes,1,opt,name=fromAddress,proto3,casttype=github.com/pokt-network/pocket-core/types.Address" json:"address"`
	ParamKey    string                                            `protobuf:"bytes,2,opt,name=paramKey,proto3" json:"param_key"`
	ParamVal    []byte                                            `protobuf:"bytes,3,opt,name=paramVal,proto3" json:"param_value"`
}

func (m *MsgChangeParam) Reset()         { *m = MsgChangeParam{} }
func (m *MsgChangeParam) String() string { return proto.CompactTextString(m) }
func (*MsgChangeParam) ProtoMessage()    {}
func (*MsgChangeParam) Descriptor() ([]byte, []int) {
	return fileDescriptor_8366cfab811ef854, []int{0}
}
func (m *MsgChangeParam) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *MsgChangeParam) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_MsgChangeParam.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *MsgChangeParam) XXX_Merge(src proto.Message) {
	xxx_messageInfo_MsgChangeParam.Merge(m, src)
}
func (m *MsgChangeParam) XXX_Size() int {
	return m.Size()
}
func (m *MsgChangeParam) XXX_DiscardUnknown() {
	xxx_messageInfo_MsgChangeParam.DiscardUnknown(m)
}

var xxx_messageInfo_MsgChangeParam proto.InternalMessageInfo

func (m *MsgChangeParam) GetFromAddress() github_com_pokt_network_pocket_core_types.Address {
	if m != nil {
		return m.FromAddress
	}
	return nil
}

func (m *MsgChangeParam) GetParamKey() string {
	if m != nil {
		return m.ParamKey
	}
	return ""
}

func (m *MsgChangeParam) GetParamVal() []byte {
	if m != nil {
		return m.ParamVal
	}
	return nil
}

func (*MsgChangeParam) XXX_MessageName() string {
	return "x.gov.MsgChangeParam"
}

type MsgDAOTransfer struct {
	FromAddress github_com_pokt_network_pocket_core_types.Address `protobuf:"bytes,1,opt,name=fromAddress,proto3,casttype=github.com/pokt-network/pocket-core/types.Address" json:"from_address"`
	ToAddress   github_com_pokt_network_pocket_core_types.Address `protobuf:"bytes,2,opt,name=toAddress,proto3,casttype=github.com/pokt-network/pocket-core/types.Address" json:"to_address"`
	Amount      github_com_pokt_network_pocket_core_types.BigInt  `protobuf:"bytes,3,opt,name=amount,proto3,customtype=github.com/pokt-network/pocket-core/types.BigInt" json:"amount"`
	Action      string                                            `protobuf:"bytes,4,opt,name=action,proto3" json:"action"`
}

func (m *MsgDAOTransfer) Reset()         { *m = MsgDAOTransfer{} }
func (m *MsgDAOTransfer) String() string { return proto.CompactTextString(m) }
func (*MsgDAOTransfer) ProtoMessage()    {}
func (*MsgDAOTransfer) Descriptor() ([]byte, []int) {
	return fileDescriptor_8366cfab811ef854, []int{1}
}
func (m *MsgDAOTransfer) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *MsgDAOTransfer) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_MsgDAOTransfer.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *MsgDAOTransfer) XXX_Merge(src proto.Message) {
	xxx_messageInfo_MsgDAOTransfer.Merge(m, src)
}
func (m *MsgDAOTransfer) XXX_Size() int {
	return m.Size()
}
func (m *MsgDAOTransfer) XXX_DiscardUnknown() {
	xxx_messageInfo_MsgDAOTransfer.DiscardUnknown(m)
}

var xxx_messageInfo_MsgDAOTransfer proto.InternalMessageInfo

func (m *MsgDAOTransfer) GetFromAddress() github_com_pokt_network_pocket_core_types.Address {
	if m != nil {
		return m.FromAddress
	}
	return nil
}

func (m *MsgDAOTransfer) GetToAddress() github_com_pokt_network_pocket_core_types.Address {
	if m != nil {
		return m.ToAddress
	}
	return nil
}

func (m *MsgDAOTransfer) GetAction() string {
	if m != nil {
		return m.Action
	}
	return ""
}

func (*MsgDAOTransfer) XXX_MessageName() string {
	return "x.gov.MsgDAOTransfer"
}

type MsgUpgrade struct {
	Address github_com_pokt_network_pocket_core_types.Address `protobuf:"bytes,1,opt,name=address,proto3,casttype=github.com/pokt-network/pocket-core/types.Address" json:"address"`
	Upgrade Upgrade                                           `protobuf:"bytes,2,opt,name=upgrade,proto3" json:"upgrade"`
}

func (m *MsgUpgrade) Reset()         { *m = MsgUpgrade{} }
func (m *MsgUpgrade) String() string { return proto.CompactTextString(m) }
func (*MsgUpgrade) ProtoMessage()    {}
func (*MsgUpgrade) Descriptor() ([]byte, []int) {
	return fileDescriptor_8366cfab811ef854, []int{2}
}
func (m *MsgUpgrade) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *MsgUpgrade) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_MsgUpgrade.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *MsgUpgrade) XXX_Merge(src proto.Message) {
	xxx_messageInfo_MsgUpgrade.Merge(m, src)
}
func (m *MsgUpgrade) XXX_Size() int {
	return m.Size()
}
func (m *MsgUpgrade) XXX_DiscardUnknown() {
	xxx_messageInfo_MsgUpgrade.DiscardUnknown(m)
}

var xxx_messageInfo_MsgUpgrade proto.InternalMessageInfo

func (m *MsgUpgrade) GetAddress() github_com_pokt_network_pocket_core_types.Address {
	if m != nil {
		return m.Address
	}
	return nil
}

func (m *MsgUpgrade) GetUpgrade() Upgrade {
	if m != nil {
		return m.Upgrade
	}
	return Upgrade{}
}

func (*MsgUpgrade) XXX_MessageName() string {
	return "x.gov.MsgUpgrade"
}

type Upgrade struct {
	Height  int64  `protobuf:"varint,1,opt,name=height,proto3" json:"Height"`
	Version string `protobuf:"bytes,2,opt,name=version,proto3" json:"Version"`
}

func (m *Upgrade) Reset()         { *m = Upgrade{} }
func (m *Upgrade) String() string { return proto.CompactTextString(m) }
func (*Upgrade) ProtoMessage()    {}
func (*Upgrade) Descriptor() ([]byte, []int) {
	return fileDescriptor_8366cfab811ef854, []int{3}
}
func (m *Upgrade) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *Upgrade) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_Upgrade.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *Upgrade) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Upgrade.Merge(m, src)
}
func (m *Upgrade) XXX_Size() int {
	return m.Size()
}
func (m *Upgrade) XXX_DiscardUnknown() {
	xxx_messageInfo_Upgrade.DiscardUnknown(m)
}

var xxx_messageInfo_Upgrade proto.InternalMessageInfo

func (m *Upgrade) GetHeight() int64 {
	if m != nil {
		return m.Height
	}
	return 0
}

func (m *Upgrade) GetVersion() string {
	if m != nil {
		return m.Version
	}
	return ""
}

type ACLPair struct {
	Key  string                                            `protobuf:"bytes,1,opt,name=key,proto3" json:"acl_key"`
	Addr github_com_pokt_network_pocket_core_types.Address `protobuf:"bytes,2,opt,name=addr,proto3,casttype=github.com/pokt-network/pocket-core/types.Address" json:"address"`
}

func (m *ACLPair) Reset()         { *m = ACLPair{} }
func (m *ACLPair) String() string { return proto.CompactTextString(m) }
func (*ACLPair) ProtoMessage()    {}
func (*ACLPair) Descriptor() ([]byte, []int) {
	return fileDescriptor_8366cfab811ef854, []int{4}
}
func (m *ACLPair) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *ACLPair) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_ACLPair.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *ACLPair) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ACLPair.Merge(m, src)
}
func (m *ACLPair) XXX_Size() int {
	return m.Size()
}
func (m *ACLPair) XXX_DiscardUnknown() {
	xxx_messageInfo_ACLPair.DiscardUnknown(m)
}

var xxx_messageInfo_ACLPair proto.InternalMessageInfo

func (m *ACLPair) GetKey() string {
	if m != nil {
		return m.Key
	}
	return ""
}

func (m *ACLPair) GetAddr() github_com_pokt_network_pocket_core_types.Address {
	if m != nil {
		return m.Addr
	}
	return nil
}

func init() {
	proto.RegisterType((*MsgChangeParam)(nil), "x.gov.MsgChangeParam")
	proto.RegisterType((*MsgDAOTransfer)(nil), "x.gov.MsgDAOTransfer")
	proto.RegisterType((*MsgUpgrade)(nil), "x.gov.MsgUpgrade")
	proto.RegisterType((*Upgrade)(nil), "x.gov.Upgrade")
	proto.RegisterType((*ACLPair)(nil), "x.gov.ACLPair")
}

func init() { proto.RegisterFile("x/gov/gov.proto", fileDescriptor_8366cfab811ef854) }

var fileDescriptor_8366cfab811ef854 = []byte{
	// 512 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xac, 0x54, 0xbf, 0x6f, 0xd3, 0x40,
	0x14, 0x8e, 0x9b, 0x90, 0x90, 0x97, 0xd2, 0x48, 0x27, 0x86, 0x08, 0x09, 0x5f, 0x65, 0x09, 0xa9,
	0x08, 0xd5, 0xe6, 0xc7, 0x04, 0x13, 0x71, 0x40, 0xa2, 0x82, 0x8a, 0xca, 0x0a, 0x1d, 0xb2, 0x54,
	0x17, 0xe7, 0x7a, 0xb1, 0x9c, 0xf8, 0xac, 0xf3, 0x25, 0x34, 0x0b, 0x33, 0x23, 0x7f, 0x03, 0x1b,
	0xff, 0x49, 0xc7, 0x8a, 0x09, 0x31, 0x58, 0x28, 0xd9, 0xfc, 0x27, 0x30, 0xa1, 0x3b, 0x9f, 0x0b,
	0x03, 0x43, 0xa5, 0x76, 0xb0, 0xee, 0xf4, 0xbd, 0xe7, 0xef, 0x7b, 0xef, 0xd3, 0xa7, 0x83, 0xee,
	0x99, 0xc7, 0xf8, 0x52, 0x7d, 0x6e, 0x2a, 0xb8, 0xe4, 0xe8, 0xd6, 0x99, 0xcb, 0xf8, 0xf2, 0xde,
	0x5d, 0xc6, 0x19, 0xd7, 0x88, 0xa7, 0x6e, 0x65, 0xd1, 0xf9, 0x6e, 0xc1, 0xce, 0x61, 0xc6, 0x06,
	0x53, 0x92, 0x30, 0x7a, 0x44, 0x04, 0x99, 0xa3, 0x31, 0x74, 0x4e, 0x05, 0x9f, 0xf7, 0x27, 0x13,
	0x41, 0xb3, 0xac, 0x67, 0xed, 0x5a, 0x7b, 0xdb, 0xfe, 0xcb, 0x22, 0xc7, 0x2d, 0x52, 0x42, 0xbf,
	0x73, 0xfc, 0x84, 0x45, 0x72, 0xba, 0x18, 0xbb, 0x21, 0x9f, 0x7b, 0x29, 0x8f, 0xe5, 0x7e, 0x42,
	0xe5, 0x47, 0x2e, 0x62, 0x2f, 0xe5, 0x61, 0x4c, 0xe5, 0x7e, 0xc8, 0x05, 0xf5, 0xe4, 0x2a, 0xa5,
	0x99, 0x6b, 0x78, 0x82, 0x7f, 0x49, 0xd1, 0x43, 0xb8, 0x9d, 0x2a, 0xb1, 0xb7, 0x74, 0xd5, 0xdb,
	0xda, 0xb5, 0xf6, 0xda, 0xfe, 0x9d, 0x22, 0xc7, 0x6d, 0x8d, 0x9d, 0xc4, 0x74, 0x15, 0x5c, 0x96,
	0xd1, 0x23, 0xd3, 0x7a, 0x4c, 0x66, 0xbd, 0xba, 0x9e, 0xa5, 0x5b, 0xe4, 0xb8, 0x53, 0xb6, 0x2e,
	0xc9, 0x6c, 0x41, 0x83, 0xcb, 0x86, 0x17, 0x8d, 0xcf, 0x5f, 0xb1, 0xe5, 0xac, 0xb7, 0xf4, 0x52,
	0xaf, 0xfa, 0xef, 0x87, 0x82, 0x24, 0xd9, 0x29, 0x15, 0x88, 0xfd, 0x6f, 0xa9, 0xd7, 0x45, 0x8e,
	0xb7, 0x15, 0x7c, 0x72, 0x73, 0x9b, 0x11, 0x68, 0x4b, 0x5e, 0xc9, 0x6c, 0x69, 0x99, 0x41, 0x91,
	0x63, 0x90, 0xfc, 0x7a, 0x22, 0x7f, 0x59, 0xd1, 0x08, 0x9a, 0x64, 0xce, 0x17, 0x89, 0xd4, 0x7e,
	0xb4, 0x7d, 0xff, 0x3c, 0xc7, 0xb5, 0x9f, 0x39, 0x7e, 0x7c, 0x75, 0x56, 0x3f, 0x62, 0x07, 0x89,
	0x2c, 0x72, 0x6c, 0x98, 0x02, 0x73, 0x22, 0x07, 0x9a, 0x24, 0x94, 0x11, 0x4f, 0x7a, 0x0d, 0xcd,
	0x0d, 0xba, 0x47, 0x23, 0x81, 0x39, 0x8d, 0xc9, 0xdf, 0x2c, 0x80, 0xc3, 0x8c, 0x7d, 0x48, 0x99,
	0x20, 0x13, 0x8a, 0x46, 0x50, 0xc5, 0xe3, 0xc6, 0x12, 0x53, 0xfd, 0x8d, 0x9e, 0x43, 0x6b, 0x51,
	0xca, 0x68, 0x47, 0x3b, 0x4f, 0x77, 0x5c, 0x9d, 0x69, 0xd7, 0x88, 0xfb, 0x5d, 0xe5, 0x80, 0xd2,
	0x33, 0x6d, 0x41, 0x75, 0x31, 0xb3, 0x0e, 0xa1, 0x55, 0xcd, 0xe9, 0x40, 0x73, 0x4a, 0x23, 0x36,
	0x95, 0x7a, 0xcc, 0x7a, 0xb9, 0xe0, 0x1b, 0x8d, 0x04, 0xa6, 0x82, 0x1e, 0x40, 0x6b, 0x49, 0x45,
	0xa6, 0x5c, 0x28, 0xc3, 0xd9, 0x51, 0xdc, 0xc7, 0x25, 0x14, 0x54, 0x35, 0xe7, 0x13, 0xb4, 0xfa,
	0x83, 0x77, 0x47, 0x24, 0x12, 0xe8, 0x3e, 0xd4, 0x63, 0xba, 0xd2, 0x94, 0xa6, 0x9b, 0x84, 0x33,
	0x1d, 0x64, 0x85, 0xa3, 0x21, 0x34, 0xd4, 0x2e, 0x26, 0x0f, 0xd7, 0x77, 0x46, 0xb3, 0xf9, 0x07,
	0xe7, 0x6b, 0xdb, 0xba, 0x58, 0xdb, 0xd6, 0xaf, 0xb5, 0x6d, 0x7d, 0xd9, 0xd8, 0xb5, 0x8b, 0x8d,
	0x5d, 0xfb, 0xb1, 0xb1, 0x6b, 0x23, 0xef, 0x2a, 0x94, 0xe5, 0x3b, 0xa1, 0x89, 0xc7, 0x4d, 0xfd,
	0x1a, 0x3c, 0xfb, 0x13, 0x00, 0x00, 0xff, 0xff, 0xaa, 0x34, 0x01, 0xd7, 0x3d, 0x04, 0x00, 0x00,
}

func (m *MsgChangeParam) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *MsgChangeParam) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *MsgChangeParam) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if len(m.ParamVal) > 0 {
		i -= len(m.ParamVal)
		copy(dAtA[i:], m.ParamVal)
		i = encodeVarintGov(dAtA, i, uint64(len(m.ParamVal)))
		i--
		dAtA[i] = 0x1a
	}
	if len(m.ParamKey) > 0 {
		i -= len(m.ParamKey)
		copy(dAtA[i:], m.ParamKey)
		i = encodeVarintGov(dAtA, i, uint64(len(m.ParamKey)))
		i--
		dAtA[i] = 0x12
	}
	if len(m.FromAddress) > 0 {
		i -= len(m.FromAddress)
		copy(dAtA[i:], m.FromAddress)
		i = encodeVarintGov(dAtA, i, uint64(len(m.FromAddress)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *MsgDAOTransfer) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *MsgDAOTransfer) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *MsgDAOTransfer) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if len(m.Action) > 0 {
		i -= len(m.Action)
		copy(dAtA[i:], m.Action)
		i = encodeVarintGov(dAtA, i, uint64(len(m.Action)))
		i--
		dAtA[i] = 0x22
	}
	{
		size := m.Amount.Size()
		i -= size
		if _, err := m.Amount.MarshalTo(dAtA[i:]); err != nil {
			return 0, err
		}
		i = encodeVarintGov(dAtA, i, uint64(size))
	}
	i--
	dAtA[i] = 0x1a
	if len(m.ToAddress) > 0 {
		i -= len(m.ToAddress)
		copy(dAtA[i:], m.ToAddress)
		i = encodeVarintGov(dAtA, i, uint64(len(m.ToAddress)))
		i--
		dAtA[i] = 0x12
	}
	if len(m.FromAddress) > 0 {
		i -= len(m.FromAddress)
		copy(dAtA[i:], m.FromAddress)
		i = encodeVarintGov(dAtA, i, uint64(len(m.FromAddress)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *MsgUpgrade) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *MsgUpgrade) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *MsgUpgrade) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	{
		size, err := m.Upgrade.MarshalToSizedBuffer(dAtA[:i])
		if err != nil {
			return 0, err
		}
		i -= size
		i = encodeVarintGov(dAtA, i, uint64(size))
	}
	i--
	dAtA[i] = 0x12
	if len(m.Address) > 0 {
		i -= len(m.Address)
		copy(dAtA[i:], m.Address)
		i = encodeVarintGov(dAtA, i, uint64(len(m.Address)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *Upgrade) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *Upgrade) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *Upgrade) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if len(m.Version) > 0 {
		i -= len(m.Version)
		copy(dAtA[i:], m.Version)
		i = encodeVarintGov(dAtA, i, uint64(len(m.Version)))
		i--
		dAtA[i] = 0x12
	}
	if m.Height != 0 {
		i = encodeVarintGov(dAtA, i, uint64(m.Height))
		i--
		dAtA[i] = 0x8
	}
	return len(dAtA) - i, nil
}

func (m *ACLPair) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *ACLPair) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *ACLPair) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if len(m.Addr) > 0 {
		i -= len(m.Addr)
		copy(dAtA[i:], m.Addr)
		i = encodeVarintGov(dAtA, i, uint64(len(m.Addr)))
		i--
		dAtA[i] = 0x12
	}
	if len(m.Key) > 0 {
		i -= len(m.Key)
		copy(dAtA[i:], m.Key)
		i = encodeVarintGov(dAtA, i, uint64(len(m.Key)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func encodeVarintGov(dAtA []byte, offset int, v uint64) int {
	offset -= sovGov(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *MsgChangeParam) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.FromAddress)
	if l > 0 {
		n += 1 + l + sovGov(uint64(l))
	}
	l = len(m.ParamKey)
	if l > 0 {
		n += 1 + l + sovGov(uint64(l))
	}
	l = len(m.ParamVal)
	if l > 0 {
		n += 1 + l + sovGov(uint64(l))
	}
	return n
}

func (m *MsgDAOTransfer) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.FromAddress)
	if l > 0 {
		n += 1 + l + sovGov(uint64(l))
	}
	l = len(m.ToAddress)
	if l > 0 {
		n += 1 + l + sovGov(uint64(l))
	}
	l = m.Amount.Size()
	n += 1 + l + sovGov(uint64(l))
	l = len(m.Action)
	if l > 0 {
		n += 1 + l + sovGov(uint64(l))
	}
	return n
}

func (m *MsgUpgrade) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.Address)
	if l > 0 {
		n += 1 + l + sovGov(uint64(l))
	}
	l = m.Upgrade.Size()
	n += 1 + l + sovGov(uint64(l))
	return n
}

func (m *Upgrade) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.Height != 0 {
		n += 1 + sovGov(uint64(m.Height))
	}
	l = len(m.Version)
	if l > 0 {
		n += 1 + l + sovGov(uint64(l))
	}
	return n
}

func (m *ACLPair) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.Key)
	if l > 0 {
		n += 1 + l + sovGov(uint64(l))
	}
	l = len(m.Addr)
	if l > 0 {
		n += 1 + l + sovGov(uint64(l))
	}
	return n
}

func sovGov(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozGov(x uint64) (n int) {
	return sovGov(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *MsgChangeParam) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowGov
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: MsgChangeParam: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: MsgChangeParam: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field FromAddress", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowGov
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthGov
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthGov
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.FromAddress = append(m.FromAddress[:0], dAtA[iNdEx:postIndex]...)
			if m.FromAddress == nil {
				m.FromAddress = []byte{}
			}
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field ParamKey", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowGov
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthGov
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthGov
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.ParamKey = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field ParamVal", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowGov
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthGov
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthGov
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.ParamVal = append(m.ParamVal[:0], dAtA[iNdEx:postIndex]...)
			if m.ParamVal == nil {
				m.ParamVal = []byte{}
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipGov(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthGov
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthGov
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *MsgDAOTransfer) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowGov
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: MsgDAOTransfer: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: MsgDAOTransfer: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field FromAddress", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowGov
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthGov
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthGov
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.FromAddress = append(m.FromAddress[:0], dAtA[iNdEx:postIndex]...)
			if m.FromAddress == nil {
				m.FromAddress = []byte{}
			}
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field ToAddress", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowGov
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthGov
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthGov
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.ToAddress = append(m.ToAddress[:0], dAtA[iNdEx:postIndex]...)
			if m.ToAddress == nil {
				m.ToAddress = []byte{}
			}
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Amount", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowGov
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthGov
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthGov
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if err := m.Amount.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 4:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Action", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowGov
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthGov
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthGov
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Action = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipGov(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthGov
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthGov
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *MsgUpgrade) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowGov
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: MsgUpgrade: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: MsgUpgrade: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Address", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowGov
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthGov
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthGov
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Address = append(m.Address[:0], dAtA[iNdEx:postIndex]...)
			if m.Address == nil {
				m.Address = []byte{}
			}
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Upgrade", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowGov
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthGov
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthGov
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if err := m.Upgrade.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipGov(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthGov
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthGov
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *Upgrade) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowGov
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: Upgrade: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Upgrade: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Height", wireType)
			}
			m.Height = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowGov
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Height |= int64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Version", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowGov
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthGov
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthGov
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Version = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipGov(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthGov
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthGov
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *ACLPair) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowGov
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: ACLPair: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: ACLPair: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Key", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowGov
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthGov
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthGov
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Key = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Addr", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowGov
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthGov
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthGov
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Addr = append(m.Addr[:0], dAtA[iNdEx:postIndex]...)
			if m.Addr == nil {
				m.Addr = []byte{}
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipGov(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthGov
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthGov
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipGov(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowGov
			}
			if iNdEx >= l {
				return 0, io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		wireType := int(wire & 0x7)
		switch wireType {
		case 0:
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowGov
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				iNdEx++
				if dAtA[iNdEx-1] < 0x80 {
					break
				}
			}
		case 1:
			iNdEx += 8
		case 2:
			var length int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowGov
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				length |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if length < 0 {
				return 0, ErrInvalidLengthGov
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupGov
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthGov
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthGov        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowGov          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupGov = fmt.Errorf("proto: unexpected end of group")
)
