// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.32.0
// 	protoc        v5.28.1
// source: pkg/proto/configuration/bb_browser/bb_browser.proto

package bb_browser

import (
	auth "github.com/buildbarn/bb-storage/pkg/proto/configuration/auth"
	blobstore "github.com/buildbarn/bb-storage/pkg/proto/configuration/blobstore"
	global "github.com/buildbarn/bb-storage/pkg/proto/configuration/global"
	http "github.com/buildbarn/bb-storage/pkg/proto/configuration/http"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type ApplicationConfiguration struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Blobstore                              *blobstore.BlobstoreConfiguration  `protobuf:"bytes,1,opt,name=blobstore,proto3" json:"blobstore,omitempty"`
	MaximumMessageSizeBytes                int64                              `protobuf:"varint,2,opt,name=maximum_message_size_bytes,json=maximumMessageSizeBytes,proto3" json:"maximum_message_size_bytes,omitempty"`
	HttpServers                            []*http.ServerConfiguration        `protobuf:"bytes,10,rep,name=http_servers,json=httpServers,proto3" json:"http_servers,omitempty"`
	RoutePrefix                            string                             `protobuf:"bytes,7,opt,name=route_prefix,json=routePrefix,proto3" json:"route_prefix,omitempty"`
	Global                                 *global.Configuration              `protobuf:"bytes,4,opt,name=global,proto3" json:"global,omitempty"`
	BbClientdInstanceNamePrefix            string                             `protobuf:"bytes,5,opt,name=bb_clientd_instance_name_prefix,json=bbClientdInstanceNamePrefix,proto3" json:"bb_clientd_instance_name_prefix,omitempty"`
	InitialSizeClassCache                  *blobstore.BlobAccessConfiguration `protobuf:"bytes,6,opt,name=initial_size_class_cache,json=initialSizeClassCache,proto3" json:"initial_size_class_cache,omitempty"`
	FileSystemAccessCache                  *blobstore.BlobAccessConfiguration `protobuf:"bytes,9,opt,name=file_system_access_cache,json=fileSystemAccessCache,proto3" json:"file_system_access_cache,omitempty"`
	Authorizer                             *auth.AuthorizerConfiguration      `protobuf:"bytes,8,opt,name=authorizer,proto3" json:"authorizer,omitempty"`
	RequestMetadataLinksJmespathExpression string                             `protobuf:"bytes,11,opt,name=request_metadata_links_jmespath_expression,json=requestMetadataLinksJmespathExpression,proto3" json:"request_metadata_links_jmespath_expression,omitempty"`
}

func (x *ApplicationConfiguration) Reset() {
	*x = ApplicationConfiguration{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_proto_configuration_bb_browser_bb_browser_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ApplicationConfiguration) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ApplicationConfiguration) ProtoMessage() {}

func (x *ApplicationConfiguration) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_proto_configuration_bb_browser_bb_browser_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ApplicationConfiguration.ProtoReflect.Descriptor instead.
func (*ApplicationConfiguration) Descriptor() ([]byte, []int) {
	return file_pkg_proto_configuration_bb_browser_bb_browser_proto_rawDescGZIP(), []int{0}
}

func (x *ApplicationConfiguration) GetBlobstore() *blobstore.BlobstoreConfiguration {
	if x != nil {
		return x.Blobstore
	}
	return nil
}

func (x *ApplicationConfiguration) GetMaximumMessageSizeBytes() int64 {
	if x != nil {
		return x.MaximumMessageSizeBytes
	}
	return 0
}

func (x *ApplicationConfiguration) GetHttpServers() []*http.ServerConfiguration {
	if x != nil {
		return x.HttpServers
	}
	return nil
}

func (x *ApplicationConfiguration) GetRoutePrefix() string {
	if x != nil {
		return x.RoutePrefix
	}
	return ""
}

func (x *ApplicationConfiguration) GetGlobal() *global.Configuration {
	if x != nil {
		return x.Global
	}
	return nil
}

func (x *ApplicationConfiguration) GetBbClientdInstanceNamePrefix() string {
	if x != nil {
		return x.BbClientdInstanceNamePrefix
	}
	return ""
}

func (x *ApplicationConfiguration) GetInitialSizeClassCache() *blobstore.BlobAccessConfiguration {
	if x != nil {
		return x.InitialSizeClassCache
	}
	return nil
}

func (x *ApplicationConfiguration) GetFileSystemAccessCache() *blobstore.BlobAccessConfiguration {
	if x != nil {
		return x.FileSystemAccessCache
	}
	return nil
}

func (x *ApplicationConfiguration) GetAuthorizer() *auth.AuthorizerConfiguration {
	if x != nil {
		return x.Authorizer
	}
	return nil
}

func (x *ApplicationConfiguration) GetRequestMetadataLinksJmespathExpression() string {
	if x != nil {
		return x.RequestMetadataLinksJmespathExpression
	}
	return ""
}

var File_pkg_proto_configuration_bb_browser_bb_browser_proto protoreflect.FileDescriptor

var file_pkg_proto_configuration_bb_browser_bb_browser_proto_rawDesc = []byte{
	0x0a, 0x33, 0x70, 0x6b, 0x67, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x63, 0x6f, 0x6e, 0x66,
	0x69, 0x67, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x62, 0x62, 0x5f, 0x62, 0x72, 0x6f,
	0x77, 0x73, 0x65, 0x72, 0x2f, 0x62, 0x62, 0x5f, 0x62, 0x72, 0x6f, 0x77, 0x73, 0x65, 0x72, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x22, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x62, 0x61, 0x72, 0x6e,
	0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x62,
	0x62, 0x5f, 0x62, 0x72, 0x6f, 0x77, 0x73, 0x65, 0x72, 0x1a, 0x27, 0x70, 0x6b, 0x67, 0x2f, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x2f, 0x61, 0x75, 0x74, 0x68, 0x2f, 0x61, 0x75, 0x74, 0x68, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x1a, 0x31, 0x70, 0x6b, 0x67, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x63, 0x6f,
	0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x62, 0x6c, 0x6f, 0x62,
	0x73, 0x74, 0x6f, 0x72, 0x65, 0x2f, 0x62, 0x6c, 0x6f, 0x62, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x2b, 0x70, 0x6b, 0x67, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x67,
	0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x2f, 0x67, 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x1a, 0x27, 0x70, 0x6b, 0x67, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x63, 0x6f,
	0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x68, 0x74, 0x74, 0x70,
	0x2f, 0x68, 0x74, 0x74, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xd9, 0x06, 0x0a, 0x18,
	0x41, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x43, 0x6f, 0x6e, 0x66, 0x69,
	0x67, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x57, 0x0a, 0x09, 0x62, 0x6c, 0x6f, 0x62,
	0x73, 0x74, 0x6f, 0x72, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x39, 0x2e, 0x62, 0x75,
	0x69, 0x6c, 0x64, 0x62, 0x61, 0x72, 0x6e, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75, 0x72,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x62, 0x6c, 0x6f, 0x62, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2e,
	0x42, 0x6c, 0x6f, 0x62, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75,
	0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x09, 0x62, 0x6c, 0x6f, 0x62, 0x73, 0x74, 0x6f, 0x72,
	0x65, 0x12, 0x3b, 0x0a, 0x1a, 0x6d, 0x61, 0x78, 0x69, 0x6d, 0x75, 0x6d, 0x5f, 0x6d, 0x65, 0x73,
	0x73, 0x61, 0x67, 0x65, 0x5f, 0x73, 0x69, 0x7a, 0x65, 0x5f, 0x62, 0x79, 0x74, 0x65, 0x73, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x03, 0x52, 0x17, 0x6d, 0x61, 0x78, 0x69, 0x6d, 0x75, 0x6d, 0x4d, 0x65,
	0x73, 0x73, 0x61, 0x67, 0x65, 0x53, 0x69, 0x7a, 0x65, 0x42, 0x79, 0x74, 0x65, 0x73, 0x12, 0x54,
	0x0a, 0x0c, 0x68, 0x74, 0x74, 0x70, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x73, 0x18, 0x0a,
	0x20, 0x03, 0x28, 0x0b, 0x32, 0x31, 0x2e, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x62, 0x61, 0x72, 0x6e,
	0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x68,
	0x74, 0x74, 0x70, 0x2e, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67,
	0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x0b, 0x68, 0x74, 0x74, 0x70, 0x53, 0x65, 0x72,
	0x76, 0x65, 0x72, 0x73, 0x12, 0x21, 0x0a, 0x0c, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x5f, 0x70, 0x72,
	0x65, 0x66, 0x69, 0x78, 0x18, 0x07, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x72, 0x6f, 0x75, 0x74,
	0x65, 0x50, 0x72, 0x65, 0x66, 0x69, 0x78, 0x12, 0x45, 0x0a, 0x06, 0x67, 0x6c, 0x6f, 0x62, 0x61,
	0x6c, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2d, 0x2e, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x62,
	0x61, 0x72, 0x6e, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f,
	0x6e, 0x2e, 0x67, 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x2e, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75,
	0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x06, 0x67, 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x12, 0x44,
	0x0a, 0x1f, 0x62, 0x62, 0x5f, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x64, 0x5f, 0x69, 0x6e, 0x73,
	0x74, 0x61, 0x6e, 0x63, 0x65, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x5f, 0x70, 0x72, 0x65, 0x66, 0x69,
	0x78, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x52, 0x1b, 0x62, 0x62, 0x43, 0x6c, 0x69, 0x65, 0x6e,
	0x74, 0x64, 0x49, 0x6e, 0x73, 0x74, 0x61, 0x6e, 0x63, 0x65, 0x4e, 0x61, 0x6d, 0x65, 0x50, 0x72,
	0x65, 0x66, 0x69, 0x78, 0x12, 0x73, 0x0a, 0x18, 0x69, 0x6e, 0x69, 0x74, 0x69, 0x61, 0x6c, 0x5f,
	0x73, 0x69, 0x7a, 0x65, 0x5f, 0x63, 0x6c, 0x61, 0x73, 0x73, 0x5f, 0x63, 0x61, 0x63, 0x68, 0x65,
	0x18, 0x06, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x3a, 0x2e, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x62, 0x61,
	0x72, 0x6e, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e,
	0x2e, 0x62, 0x6c, 0x6f, 0x62, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2e, 0x42, 0x6c, 0x6f, 0x62, 0x41,
	0x63, 0x63, 0x65, 0x73, 0x73, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x52, 0x15, 0x69, 0x6e, 0x69, 0x74, 0x69, 0x61, 0x6c, 0x53, 0x69, 0x7a, 0x65, 0x43,
	0x6c, 0x61, 0x73, 0x73, 0x43, 0x61, 0x63, 0x68, 0x65, 0x12, 0x73, 0x0a, 0x18, 0x66, 0x69, 0x6c,
	0x65, 0x5f, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x5f, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x5f,
	0x63, 0x61, 0x63, 0x68, 0x65, 0x18, 0x09, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x3a, 0x2e, 0x62, 0x75,
	0x69, 0x6c, 0x64, 0x62, 0x61, 0x72, 0x6e, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75, 0x72,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x62, 0x6c, 0x6f, 0x62, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2e,
	0x42, 0x6c, 0x6f, 0x62, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67,
	0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x15, 0x66, 0x69, 0x6c, 0x65, 0x53, 0x79, 0x73,
	0x74, 0x65, 0x6d, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x43, 0x61, 0x63, 0x68, 0x65, 0x12, 0x55,
	0x0a, 0x0a, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x72, 0x18, 0x08, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x35, 0x2e, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x62, 0x61, 0x72, 0x6e, 0x2e, 0x63,
	0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x61, 0x75, 0x74,
	0x68, 0x2e, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x72, 0x43, 0x6f, 0x6e, 0x66,
	0x69, 0x67, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x0a, 0x61, 0x75, 0x74, 0x68, 0x6f,
	0x72, 0x69, 0x7a, 0x65, 0x72, 0x12, 0x5a, 0x0a, 0x2a, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x5f, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x5f, 0x6c, 0x69, 0x6e, 0x6b, 0x73, 0x5f,
	0x6a, 0x6d, 0x65, 0x73, 0x70, 0x61, 0x74, 0x68, 0x5f, 0x65, 0x78, 0x70, 0x72, 0x65, 0x73, 0x73,
	0x69, 0x6f, 0x6e, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x09, 0x52, 0x26, 0x72, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x4c, 0x69, 0x6e, 0x6b, 0x73, 0x4a,
	0x6d, 0x65, 0x73, 0x70, 0x61, 0x74, 0x68, 0x45, 0x78, 0x70, 0x72, 0x65, 0x73, 0x73, 0x69, 0x6f,
	0x6e, 0x4a, 0x04, 0x08, 0x03, 0x10, 0x04, 0x42, 0x44, 0x5a, 0x42, 0x67, 0x69, 0x74, 0x68, 0x75,
	0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x62, 0x61, 0x72, 0x6e, 0x2f,
	0x62, 0x62, 0x2d, 0x62, 0x72, 0x6f, 0x77, 0x73, 0x65, 0x72, 0x2f, 0x70, 0x6b, 0x67, 0x2f, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x2f, 0x62, 0x62, 0x5f, 0x62, 0x72, 0x6f, 0x77, 0x73, 0x65, 0x72, 0x62, 0x06, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_pkg_proto_configuration_bb_browser_bb_browser_proto_rawDescOnce sync.Once
	file_pkg_proto_configuration_bb_browser_bb_browser_proto_rawDescData = file_pkg_proto_configuration_bb_browser_bb_browser_proto_rawDesc
)

func file_pkg_proto_configuration_bb_browser_bb_browser_proto_rawDescGZIP() []byte {
	file_pkg_proto_configuration_bb_browser_bb_browser_proto_rawDescOnce.Do(func() {
		file_pkg_proto_configuration_bb_browser_bb_browser_proto_rawDescData = protoimpl.X.CompressGZIP(file_pkg_proto_configuration_bb_browser_bb_browser_proto_rawDescData)
	})
	return file_pkg_proto_configuration_bb_browser_bb_browser_proto_rawDescData
}

var file_pkg_proto_configuration_bb_browser_bb_browser_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_pkg_proto_configuration_bb_browser_bb_browser_proto_goTypes = []interface{}{
	(*ApplicationConfiguration)(nil),          // 0: buildbarn.configuration.bb_browser.ApplicationConfiguration
	(*blobstore.BlobstoreConfiguration)(nil),  // 1: buildbarn.configuration.blobstore.BlobstoreConfiguration
	(*http.ServerConfiguration)(nil),          // 2: buildbarn.configuration.http.ServerConfiguration
	(*global.Configuration)(nil),              // 3: buildbarn.configuration.global.Configuration
	(*blobstore.BlobAccessConfiguration)(nil), // 4: buildbarn.configuration.blobstore.BlobAccessConfiguration
	(*auth.AuthorizerConfiguration)(nil),      // 5: buildbarn.configuration.auth.AuthorizerConfiguration
}
var file_pkg_proto_configuration_bb_browser_bb_browser_proto_depIdxs = []int32{
	1, // 0: buildbarn.configuration.bb_browser.ApplicationConfiguration.blobstore:type_name -> buildbarn.configuration.blobstore.BlobstoreConfiguration
	2, // 1: buildbarn.configuration.bb_browser.ApplicationConfiguration.http_servers:type_name -> buildbarn.configuration.http.ServerConfiguration
	3, // 2: buildbarn.configuration.bb_browser.ApplicationConfiguration.global:type_name -> buildbarn.configuration.global.Configuration
	4, // 3: buildbarn.configuration.bb_browser.ApplicationConfiguration.initial_size_class_cache:type_name -> buildbarn.configuration.blobstore.BlobAccessConfiguration
	4, // 4: buildbarn.configuration.bb_browser.ApplicationConfiguration.file_system_access_cache:type_name -> buildbarn.configuration.blobstore.BlobAccessConfiguration
	5, // 5: buildbarn.configuration.bb_browser.ApplicationConfiguration.authorizer:type_name -> buildbarn.configuration.auth.AuthorizerConfiguration
	6, // [6:6] is the sub-list for method output_type
	6, // [6:6] is the sub-list for method input_type
	6, // [6:6] is the sub-list for extension type_name
	6, // [6:6] is the sub-list for extension extendee
	0, // [0:6] is the sub-list for field type_name
}

func init() { file_pkg_proto_configuration_bb_browser_bb_browser_proto_init() }
func file_pkg_proto_configuration_bb_browser_bb_browser_proto_init() {
	if File_pkg_proto_configuration_bb_browser_bb_browser_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_pkg_proto_configuration_bb_browser_bb_browser_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ApplicationConfiguration); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_pkg_proto_configuration_bb_browser_bb_browser_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_pkg_proto_configuration_bb_browser_bb_browser_proto_goTypes,
		DependencyIndexes: file_pkg_proto_configuration_bb_browser_bb_browser_proto_depIdxs,
		MessageInfos:      file_pkg_proto_configuration_bb_browser_bb_browser_proto_msgTypes,
	}.Build()
	File_pkg_proto_configuration_bb_browser_bb_browser_proto = out.File
	file_pkg_proto_configuration_bb_browser_bb_browser_proto_rawDesc = nil
	file_pkg_proto_configuration_bb_browser_bb_browser_proto_goTypes = nil
	file_pkg_proto_configuration_bb_browser_bb_browser_proto_depIdxs = nil
}
