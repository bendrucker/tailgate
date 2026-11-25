//go:build darwin && cgo

package keychain

/*
#cgo CFLAGS: -Wno-deprecated-declarations
#cgo LDFLAGS: -framework Security -framework CoreFoundation

#include <stdlib.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

static CFStringRef cfstring(const char *s) {
	return CFStringCreateWithCString(NULL, s, kCFStringEncodingUTF8);
}

static CFMutableDictionaryRef item_query(const char *service, const char *account) {
	CFMutableDictionaryRef query = CFDictionaryCreateMutable(NULL, 0,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CFStringRef s = cfstring(service);
	CFStringRef a = cfstring(account);
	CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
	CFDictionarySetValue(query, kSecAttrService, s);
	CFDictionarySetValue(query, kSecAttrAccount, a);
	CFRelease(s);
	CFRelease(a);
	return query;
}

static OSStatus keychain_read(const char *service, const char *account, CFDataRef *out) {
	SecKeychainSetUserInteractionAllowed(false);
	CFMutableDictionaryRef query = item_query(service, account);
	CFDictionarySetValue(query, kSecReturnData, kCFBooleanTrue);
	CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne);
	OSStatus status = SecItemCopyMatching(query, (CFTypeRef *)out);
	CFRelease(query);
	return status;
}

// keychain_add creates the item with an access list that trusts only the calling
// binary. Any other application needs the person's consent to read it,
// and with interaction disabled none is asked for.
static OSStatus keychain_add(const char *service, const char *account, const char *label, const void *secret, int length) {
	SecKeychainSetUserInteractionAllowed(false);

	SecTrustedApplicationRef self = NULL;
	OSStatus status = SecTrustedApplicationCreateFromPath(NULL, &self);
	if (status != errSecSuccess) {
		return status;
	}
	CFArrayRef trusted = CFArrayCreate(NULL, (const void **)&self, 1, &kCFTypeArrayCallBacks);
	CFRelease(self);

	CFStringRef description = cfstring(label);
	SecAccessRef access = NULL;
	status = SecAccessCreate(description, trusted, &access);
	CFRelease(trusted);
	if (status != errSecSuccess) {
		CFRelease(description);
		return status;
	}

	CFDataRef data = CFDataCreate(NULL, secret, length);
	CFMutableDictionaryRef query = item_query(service, account);
	CFDictionarySetValue(query, kSecAttrLabel, description);
	CFDictionarySetValue(query, kSecAttrAccess, access);
	CFDictionarySetValue(query, kSecValueData, data);
	status = SecItemAdd(query, NULL);

	CFRelease(query);
	CFRelease(data);
	CFRelease(access);
	CFRelease(description);
	return status;
}

static OSStatus keychain_delete(const char *service, const char *account) {
	SecKeychainSetUserInteractionAllowed(false);
	CFMutableDictionaryRef query = item_query(service, account);
	OSStatus status = SecItemDelete(query);
	CFRelease(query);
	return status;
}

static char *status_message(OSStatus status) {
	CFStringRef message = SecCopyErrorMessageString(status, NULL);
	if (message == NULL) {
		return NULL;
	}
	CFIndex size = CFStringGetMaximumSizeForEncoding(CFStringGetLength(message), kCFStringEncodingUTF8) + 1;
	char *buf = malloc(size);
	if (buf != NULL && !CFStringGetCString(message, buf, size, kCFStringEncodingUTF8)) {
		free(buf);
		buf = NULL;
	}
	CFRelease(message);
	return buf;
}
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// Read returns the item's secret, or ErrNotFound when there is none.
func (i Item) Read() ([]byte, error) {
	service, account := C.CString(i.Service), C.CString(i.Account)
	defer C.free(unsafe.Pointer(service))
	defer C.free(unsafe.Pointer(account))

	var data C.CFDataRef
	if err := statusError("read", C.keychain_read(service, account, &data)); err != nil {
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(data))
	return C.GoBytes(unsafe.Pointer(C.CFDataGetBytePtr(data)), C.int(C.CFDataGetLength(data))), nil
}

// Add creates the item, trusted by the calling binary alone. label is what
// Keychain Access shows for it.
func (i Item) Add(label string, secret []byte) error {
	if len(secret) == 0 {
		return fmt.Errorf("keychain: add: empty secret")
	}
	service, account, description := C.CString(i.Service), C.CString(i.Account), C.CString(label)
	defer C.free(unsafe.Pointer(service))
	defer C.free(unsafe.Pointer(account))
	defer C.free(unsafe.Pointer(description))
	return statusError("add", C.keychain_add(service, account, description, unsafe.Pointer(&secret[0]), C.int(len(secret))))
}

// Delete removes the item, or returns ErrNotFound when there is none.
func (i Item) Delete() error {
	service, account := C.CString(i.Service), C.CString(i.Account)
	defer C.free(unsafe.Pointer(service))
	defer C.free(unsafe.Pointer(account))
	return statusError("delete", C.keychain_delete(service, account))
}

func statusError(op string, status C.OSStatus) error {
	switch status {
	case C.errSecSuccess:
		return nil
	case C.errSecItemNotFound:
		return ErrNotFound
	}
	message := "unknown error"
	if cmsg := C.status_message(status); cmsg != nil {
		message = C.GoString(cmsg)
		C.free(unsafe.Pointer(cmsg))
	}
	return fmt.Errorf("keychain: %s: %s (OSStatus %d)", op, message, int(status))
}
