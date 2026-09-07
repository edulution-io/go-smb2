package smb2

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	. "github.com/edulution-io/go-smb2/internal/erref"
	. "github.com/edulution-io/go-smb2/internal/smb2"

	"github.com/edulution-io/go-smb2/internal/msrpc"
)

// Dialer contains options for func (*Dialer) Dial.
type Dialer struct {
	MaxCreditBalance uint16 // if it's zero, clientMaxCreditBalance is used. (See feature.go for more details)
	Negotiator       Negotiator
	Initiator        Initiator
}

// Dial performs negotiation and authentication.
// It returns a session. It doesn't support NetBIOS transport.
// This implementation doesn't support multi-session on the same TCP connection.
// If you want to use another session, you need to prepare another TCP connection at first.
func (d *Dialer) Dial(tcpConn net.Conn) (*Session, error) {
	return d.DialContext(context.Background(), tcpConn)
}

// DialContext performs negotiation and authentication using the provided context.
// Note that returned session doesn't inherit context.
// If you want to use the same context, call Session.WithContext manually.
// This implementation doesn't support multi-session on the same TCP connection.
// If you want to use another session, you need to prepare another TCP connection at first.
func (d *Dialer) DialContext(ctx context.Context, tcpConn net.Conn) (*Session, error) {
	if ctx == nil {
		panic("nil context")
	}
	if d.Initiator == nil {
		return nil, &InternalError{"Initiator is empty"}
	}
	if i, ok := d.Initiator.(*NTLMInitiator); ok {
		if i.User == "" {
			return nil, &InternalError{"Anonymous account is not supported yet. Use guest account instead"}
		}
	}

	maxCreditBalance := d.MaxCreditBalance
	if maxCreditBalance == 0 {
		maxCreditBalance = clientMaxCreditBalance
	}

	a := openAccount(maxCreditBalance)

	conn, err := d.Negotiator.negotiate(direct(tcpConn), a, ctx)
	if err != nil {
		return nil, err
	}

	s, err := sessionSetup(conn, d.Initiator, ctx)
	if err != nil {
		return nil, err
	}

	return &Session{s: s, ctx: context.Background(), addr: tcpConn.RemoteAddr().String()}, nil
}

// Session represents a SMB session.
type Session struct {
	s    *session
	ctx  context.Context
	addr string
}

func (c *Session) WithContext(ctx context.Context) *Session {
	if ctx == nil {
		panic("nil context")
	}
	return &Session{s: c.s, ctx: ctx, addr: c.addr}
}

// Logoff invalidates the current SMB session.
func (c *Session) Logoff() error {
	return c.s.logoff(c.ctx)
}

// Mount mounts the SMB share.
// sharename must follow format like `<share>` or `\\<server>\<share>`.
// Note that the mounted share doesn't inherit session's context.
// If you want to use the same context, call Share.WithContext manually.
func (c *Session) Mount(sharename string) (*Share, error) {
	sharename = normPath(sharename)

	if !strings.ContainsRune(sharename, '\\') {
		sharename = fmt.Sprintf(`\\%s\%s`, c.addr, sharename)
	}

	if err := validateMountPath(sharename); err != nil {
		return nil, err
	}

	tc, err := treeConnect(c.s, sharename, 0, c.ctx)
	if err != nil {
		return nil, err
	}

	return &Share{treeConn: tc, ctx: context.Background()}, nil
}

func (c *Session) ListSharenames() ([]string, error) {
	servername := c.addr

	fs, err := c.Mount(fmt.Sprintf(`\\%s\IPC$`, servername))
	if err != nil {
		return nil, err
	}
	defer fs.Umount()

	fs = fs.WithContext(c.ctx)

	f, err := fs.OpenFile("srvsvc", os.O_RDWR, 0666)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	callId := rand.Uint32()

	bindReq := &IoctlRequest{
		CtlCode:           FSCTL_PIPE_TRANSCEIVE,
		OutputOffset:      0,
		OutputCount:       0,
		MaxInputResponse:  0,
		MaxOutputResponse: 4280,
		Flags:             SMB2_0_IOCTL_IS_FSCTL,
		Input: &msrpc.Bind{
			CallId: callId,
		},
	}

	output, err := f.ioctl(bindReq)
	if err != nil {
		return nil, &os.PathError{Op: "listSharenames", Path: f.name, Err: err}
	}

	r1 := msrpc.BindAckDecoder(output)
	if r1.IsInvalid() || r1.CallId() != callId {
		return nil, &os.PathError{Op: "listSharenames", Path: f.name, Err: &InvalidResponseError{"broken bind ack response format"}}
	}

	callId++

	reqReq := &IoctlRequest{
		CtlCode:          FSCTL_PIPE_TRANSCEIVE,
		OutputOffset:     0,
		OutputCount:      0,
		MaxInputResponse: 0,
		// MaxOutputResponse: 4280,
		MaxOutputResponse: 1024,
		Flags:             SMB2_0_IOCTL_IS_FSCTL,
		Input: &msrpc.NetShareEnumAllRequest{
			CallId:     callId,
			ServerName: servername,
			Level:      1, // level 1 seems to be portable
		},
	}

	output, err = f.ioctl(reqReq)
	if err != nil {
		if rerr, ok := err.(*ResponseError); ok && NtStatus(rerr.Code) == STATUS_BUFFER_OVERFLOW {
			buf := make([]byte, 4280)

			rlen := 4280 - len(output)

			n, err := f.readAt(buf[:rlen], 0)
			if err != nil {
				return nil, &os.PathError{Op: "listSharenames", Path: f.name, Err: err}
			}

			output = append(output, buf[:n]...)

			r2 := msrpc.NetShareEnumAllResponseDecoder(output)
			if r2.IsInvalid() || r2.CallId() != callId {
				return nil, &os.PathError{Op: "listSharenames", Path: f.name, Err: &InvalidResponseError{"broken net share enum response format"}}
			}

			for r2.IsIncomplete() {
				n, err := f.readAt(buf, 0)
				if err != nil {
					return nil, &os.PathError{Op: "listSharenames", Path: f.name, Err: err}
				}

				r3 := msrpc.NetShareEnumAllResponseDecoder(buf[:n])
				if r3.IsInvalid() || r3.CallId() != callId {
					return nil, &os.PathError{Op: "listSharenames", Path: f.name, Err: &InvalidResponseError{"broken net share enum response format"}}
				}

				output = append(output, r3.Buffer()...)

				r2 = msrpc.NetShareEnumAllResponseDecoder(output)
			}

			return r2.ShareNameList(), nil
		}

		return nil, &os.PathError{Op: "listSharenames", Path: f.name, Err: err}
	}

	r2 := msrpc.NetShareEnumAllResponseDecoder(output)
	if r2.IsInvalid() || r2.IsIncomplete() || r2.CallId() != callId {
		return nil, &os.PathError{Op: "listSharenames", Path: f.name, Err: &InvalidResponseError{"broken net share enum response format"}}
	}

	return r2.ShareNameList(), nil
}

// Share represents a SMB tree connection with VFS interface.
type Share struct {
	*treeConn
	ctx context.Context
}

func (fs *Share) WithContext(ctx context.Context) *Share {
	if ctx == nil {
		panic("nil context")
	}
	return &Share{
		treeConn: fs.treeConn,
		ctx:      ctx,
	}
}

// Umount disconects the current SMB tree.
func (fs *Share) Umount() error {
	return fs.treeConn.disconnect(fs.ctx)
}

func (fs *Share) Create(name string) (*File, error) {
	return fs.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
}

func (fs *Share) newFile(r CreateResponseDecoder, name string) *File {
	fd := r.FileId().Decode()

	fileStat := &FileStat{
		CreationTime:   time.Unix(0, r.CreationTime().Nanoseconds()),
		LastAccessTime: time.Unix(0, r.LastAccessTime().Nanoseconds()),
		LastWriteTime:  time.Unix(0, r.LastWriteTime().Nanoseconds()),
		ChangeTime:     time.Unix(0, r.ChangeTime().Nanoseconds()),
		EndOfFile:      r.EndofFile(),
		AllocationSize: r.AllocationSize(),
		FileAttributes: r.FileAttributes(),
		FileName:       base(name),
	}

	f := &File{fs: fs, fd: fd, name: name, fileStat: fileStat, id: fileSeq.Add(1)}

	runtime.SetFinalizer(f, (*File).close)

	return f
}

func (fs *Share) Open(name string) (*File, error) {
	return fs.OpenFile(name, os.O_RDONLY, 0)
}

func (fs *Share) OpenFile(name string, flag int, perm os.FileMode) (*File, error) {
	name = normPath(name)

	if err := validatePath("open", name, false); err != nil {
		return nil, err
	}

	var access uint32
	switch flag & (os.O_RDONLY | os.O_WRONLY | os.O_RDWR) {
	case os.O_RDONLY:
		access = GENERIC_READ
	case os.O_WRONLY:
		access = GENERIC_WRITE
	case os.O_RDWR:
		access = GENERIC_READ | GENERIC_WRITE
	}
	if flag&os.O_CREATE != 0 {
		access |= GENERIC_WRITE
	}
	if flag&os.O_APPEND != 0 {
		access &^= GENERIC_WRITE
		access |= FILE_APPEND_DATA
	}

	sharemode := uint32(FILE_SHARE_READ | FILE_SHARE_WRITE)

	var createmode uint32
	switch {
	case flag&(os.O_CREATE|os.O_EXCL) == (os.O_CREATE | os.O_EXCL):
		createmode = FILE_CREATE
	case flag&(os.O_CREATE|os.O_TRUNC) == (os.O_CREATE | os.O_TRUNC):
		createmode = FILE_OVERWRITE_IF
	case flag&os.O_CREATE == os.O_CREATE:
		createmode = FILE_OPEN_IF
	case flag&os.O_TRUNC == os.O_TRUNC:
		createmode = FILE_OVERWRITE
	default:
		createmode = FILE_OPEN
	}

	var attrs uint32 = FILE_ATTRIBUTE_NORMAL
	if perm&0200 == 0 {
		attrs = FILE_ATTRIBUTE_READONLY
	}

	req := &CreateRequest{
		SecurityFlags:        0,
		RequestedOplockLevel: SMB2_OPLOCK_LEVEL_NONE,
		ImpersonationLevel:   Impersonation,
		SmbCreateFlags:       0,
		DesiredAccess:        access,
		FileAttributes:       attrs,
		ShareAccess:          sharemode,
		CreateDisposition:    createmode,
		CreateOptions:        FILE_SYNCHRONOUS_IO_NONALERT,
	}

	f, err := fs.createFile(name, req, true)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: name, Err: err}
	}
	if flag&os.O_APPEND != 0 {
		f.seek(0, io.SeekEnd)
	}
	return f, nil
}

func (fs *Share) Mkdir(name string, perm os.FileMode) error {
	name = normPath(name)

	if err := validatePath("mkdir", name, false); err != nil {
		return err
	}

	req := &CreateRequest{
		SecurityFlags:        0,
		RequestedOplockLevel: SMB2_OPLOCK_LEVEL_NONE,
		ImpersonationLevel:   Impersonation,
		SmbCreateFlags:       0,
		DesiredAccess:        FILE_WRITE_ATTRIBUTES,
		FileAttributes:       FILE_ATTRIBUTE_NORMAL,
		ShareAccess:          FILE_SHARE_READ | FILE_SHARE_WRITE,
		CreateDisposition:    FILE_CREATE,
		CreateOptions:        FILE_DIRECTORY_FILE,
	}

	f, err := fs.createFile(name, req, false)
	if err != nil {
		return &os.PathError{Op: "mkdir", Path: name, Err: err}
	}

	err = f.close()
	if err != nil {
		return &os.PathError{Op: "mkdir", Path: name, Err: err}
	}
	return nil
}

func (fs *Share) Readlink(name string) (string, error) {
	name = normPath(name)

	if err := validatePath("readlink", name, false); err != nil {
		return "", err
	}

	create := &CreateRequest{
		SecurityFlags:        0,
		RequestedOplockLevel: SMB2_OPLOCK_LEVEL_NONE,
		ImpersonationLevel:   Impersonation,
		SmbCreateFlags:       0,
		DesiredAccess:        FILE_READ_ATTRIBUTES,
		FileAttributes:       FILE_ATTRIBUTE_NORMAL,
		ShareAccess:          FILE_SHARE_READ | FILE_SHARE_WRITE,
		CreateDisposition:    FILE_OPEN,
		CreateOptions:        FILE_OPEN_REPARSE_POINT,
	}

	f, err := fs.createFile(name, create, false)
	if err != nil {
		return "", &os.PathError{Op: "readlink", Path: name, Err: err}
	}

	req := &IoctlRequest{
		CtlCode:           FSCTL_GET_REPARSE_POINT,
		OutputOffset:      0,
		OutputCount:       0,
		MaxInputResponse:  0,
		MaxOutputResponse: uint32(f.maxTransactSize()),
		Flags:             SMB2_0_IOCTL_IS_FSCTL,
		Input:             nil,
	}

	output, err := f.ioctl(req)
	if e := f.close(); err == nil {
		err = e
	}
	if err != nil {
		return "", &os.PathError{Op: "readlink", Path: f.name, Err: err}
	}

	r := SymbolicLinkReparseDataBufferDecoder(output)
	if r.IsInvalid() {
		return "", &os.PathError{Op: "readlink", Path: f.name, Err: &InvalidResponseError{"broken symbolic link response data buffer format"}}
	}

	target := r.SubstituteName()

	switch {
	case strings.HasPrefix(target, `\??\UNC\`):
		target = `\\` + target[8:]
	case strings.HasPrefix(target, `\??\`):
		target = target[4:]
	}

	return target, nil
}

func (fs *Share) Remove(name string) error {
	err := fs.remove(name)
	if os.IsPermission(err) {
		if e := fs.Chmod(name, 0666); e != nil {
			return err
		}
		return fs.remove(name)
	}
	return err
}

func (fs *Share) remove(name string) error {
	name = normPath(name)

	if err := validatePath("remove", name, false); err != nil {
		return err
	}

	req := &CreateRequest{
		SecurityFlags:        0,
		RequestedOplockLevel: SMB2_OPLOCK_LEVEL_NONE,
		ImpersonationLevel:   Impersonation,
		SmbCreateFlags:       0,
		DesiredAccess:        DELETE,
		FileAttributes:       0,
		ShareAccess:          FILE_SHARE_DELETE,
		CreateDisposition:    FILE_OPEN,
		// CreateOptions:        FILE_OPEN_REPARSE_POINT | FILE_DELETE_ON_CLOSE,
		CreateOptions: FILE_OPEN_REPARSE_POINT,
	}
	// FILE_DELETE_ON_CLOSE doesn't work for reparse point, so use FileDispositionInformation instead

	f, err := fs.createFile(name, req, false)
	if err != nil {
		return &os.PathError{Op: "remove", Path: name, Err: err}
	}

	err = f.remove()
	if e := f.close(); err == nil {
		err = e
	}
	if err != nil {
		return &os.PathError{Op: "remove", Path: name, Err: err}
	}

	return nil
}

func (fs *Share) Rename(oldpath, newpath string) error {
	oldpath = normPath(oldpath)
	newpath = normPath(newpath)

	if err := validatePath("rename from", oldpath, false); err != nil {
		return err
	}

	if err := validatePath("rename to", newpath, false); err != nil {
		return err
	}

	create := &CreateRequest{
		SecurityFlags:        0,
		RequestedOplockLevel: SMB2_OPLOCK_LEVEL_NONE,
		ImpersonationLevel:   Impersonation,
		SmbCreateFlags:       0,
		DesiredAccess:        DELETE,
		FileAttributes:       FILE_ATTRIBUTE_NORMAL,
		ShareAccess:          FILE_SHARE_DELETE,
		CreateDisposition:    FILE_OPEN,
		CreateOptions:        FILE_OPEN_REPARSE_POINT,
	}

	f, err := fs.createFile(oldpath, create, false)
	if err != nil {
		return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: err}
	}

	info := &SetInfoRequest{
		FileInfoClass:         FileRenameInformation,
		AdditionalInformation: 0,
		Input: &FileRenameInformationType2Encoder{
			ReplaceIfExists: 0,
			RootDirectory:   0,
			FileName:        newpath,
		},
	}

	err = f.setInfo(info)
	if e := f.close(); err == nil {
		err = e
	}
	if err != nil {
		return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: err}
	}
	return nil
}

// Symlink mimics os.Symlink.
// This API should work on latest Windows and latest MacOS.
// However it may not work on Linux because Samba doesn't support reparse point well.
// Also there is a restriction on target pathname.
// Generally, a pathname begins with leading backslash (e.g `\dir\name`) can be interpreted as two ways.
// On windows, it is evaluated as a relative path, on other systems, it is evaluated as an absolute path.
// This implementation always assumes that format is absolute path.
// So, if you know the target server is Windows, you should avoid that format.
// If you want to use an absolute target path on windows, you can use // `C:\dir\name` format instead.
func (fs *Share) Symlink(target, linkpath string) error {
	target = normPath(target)
	linkpath = normPath(linkpath)

	if err := validatePath("symlink target", target, true); err != nil {
		return err
	}

	if err := validatePath("symlink linkpath", linkpath, false); err != nil {
		return err
	}

	rdbuf := new(SymbolicLinkReparseDataBuffer)

	if len(target) >= 2 && target[1] == ':' {
		if len(target) == 2 {
			return os.ErrInvalid
		}

		if target[2] != '\\' {
			rdbuf.Flags = SYMLINK_FLAG_RELATIVE
		}
		rdbuf.SubstituteName = `\??\` + target
		rdbuf.PrintName = rdbuf.SubstituteName[4:]
	} else {
		if target[0] != '\\' {
			rdbuf.Flags = SYMLINK_FLAG_RELATIVE // It's not true on window server.
		}
		rdbuf.SubstituteName = target
		rdbuf.PrintName = rdbuf.SubstituteName
	}

	create := &CreateRequest{
		SecurityFlags:        0,
		RequestedOplockLevel: SMB2_OPLOCK_LEVEL_NONE,
		ImpersonationLevel:   Impersonation,
		SmbCreateFlags:       0,
		DesiredAccess:        FILE_WRITE_ATTRIBUTES | DELETE,
		FileAttributes:       FILE_ATTRIBUTE_REPARSE_POINT,
		ShareAccess:          FILE_SHARE_READ | FILE_SHARE_WRITE,
		CreateDisposition:    FILE_CREATE,
		CreateOptions:        FILE_OPEN_REPARSE_POINT,
	}

	f, err := fs.createFile(linkpath, create, false)
	if err != nil {
		return &os.LinkError{Op: "symlink", Old: target, New: linkpath, Err: err}
	}

	req := &IoctlRequest{
		CtlCode:           FSCTL_SET_REPARSE_POINT,
		OutputOffset:      0,
		OutputCount:       0,
		MaxInputResponse:  0,
		MaxOutputResponse: 0,
		Flags:             SMB2_0_IOCTL_IS_FSCTL,
		Input:             rdbuf,
	}

	_, err = f.ioctl(req)
	if err != nil {
		f.remove()
		f.close()

		return &os.PathError{Op: "symlink", Path: f.name, Err: err}
	}

	err = f.close()
	if err != nil {
		return &os.PathError{Op: "symlink", Path: f.name, Err: err}
	}

	return nil
}

func (fs *Share) Lstat(name string) (os.FileInfo, error) {
	name = normPath(name)

	if err := validatePath("lstat", name, false); err != nil {
		return nil, err
	}

	create := &CreateRequest{
		SecurityFlags:        0,
		RequestedOplockLevel: SMB2_OPLOCK_LEVEL_NONE,
		ImpersonationLevel:   Impersonation,
		SmbCreateFlags:       0,
		DesiredAccess:        FILE_READ_ATTRIBUTES,
		FileAttributes:       FILE_ATTRIBUTE_NORMAL,
		ShareAccess:          FILE_SHARE_READ | FILE_SHARE_WRITE,
		CreateDisposition:    FILE_OPEN,
		CreateOptions:        FILE_OPEN_REPARSE_POINT,
	}

	f, err := fs.createFile(name, create, false)
	if err != nil {
		return nil, &os.PathError{Op: "stat", Path: name, Err: err}
	}

	fi, err := f.fileStat, nil
	if e := f.close(); err == nil {
		err = e
	}
	if err != nil {
		return nil, &os.PathError{Op: "stat", Path: name, Err: err}
	}
	return fi, nil
}

func (fs *Share) Stat(name string) (os.FileInfo, error) {
	name = normPath(name)

	if err := validatePath("stat", name, false); err != nil {
		return nil, err
	}

	create := &CreateRequest{
		SecurityFlags:        0,
		RequestedOplockLevel: SMB2_OPLOCK_LEVEL_NONE,
		ImpersonationLevel:   Impersonation,
		SmbCreateFlags:       0,
		DesiredAccess:        FILE_READ_ATTRIBUTES,
		FileAttributes:       FILE_ATTRIBUTE_NORMAL,
		ShareAccess:          FILE_SHARE_READ | FILE_SHARE_WRITE,
		CreateDisposition:    FILE_OPEN,
		CreateOptions:        0,
	}

	f, err := fs.createFile(name, create, true)
	if err != nil {
		return nil, &os.PathError{Op: "stat", Path: name, Err: err}
	}

	fi, err := f.fileStat, nil
	if e := f.close(); err == nil {
		err = e
	}
	if err != nil {
		return nil, &os.PathError{Op: "stat", Path: name, Err: err}
	}
	return fi, nil
}

func (fs *Share) Truncate(name string, size int64) error {
	name = normPath(name)

	if err := validatePath("truncate", name, false); err != nil {
		return err
	}

	if size < 0 {
		return os.ErrInvalid
	}

	create := &CreateRequest{
		SecurityFlags:        0,
		RequestedOplockLevel: SMB2_OPLOCK_LEVEL_NONE,
		ImpersonationLevel:   Impersonation,
		SmbCreateFlags:       0,
		DesiredAccess:        FILE_WRITE_DATA,
		FileAttributes:       FILE_ATTRIBUTE_NORMAL,
		ShareAccess:          FILE_SHARE_READ | FILE_SHARE_WRITE,
		CreateDisposition:    FILE_OPEN,
		CreateOptions:        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
	}

	f, err := fs.createFile(name, create, true)
	if err != nil {
		return &os.PathError{Op: "truncate", Path: name, Err: err}
	}

	err = f.truncate(size)
	if e := f.close(); err == nil {
		err = e
	}
	if err != nil {
		return &os.PathError{Op: "truncate", Path: name, Err: err}
	}
	return nil
}

func (fs *Share) Chtimes(name string, atime time.Time, mtime time.Time) error {
	name = normPath(name)

	if err := validatePath("chtimes", name, false); err != nil {
		return err
	}

	create := &CreateRequest{
		SecurityFlags:        0,
		RequestedOplockLevel: SMB2_OPLOCK_LEVEL_NONE,
		ImpersonationLevel:   Impersonation,
		SmbCreateFlags:       0,
		DesiredAccess:        FILE_WRITE_ATTRIBUTES,
		FileAttributes:       FILE_ATTRIBUTE_NORMAL,
		ShareAccess:          FILE_SHARE_READ | FILE_SHARE_WRITE,
		CreateDisposition:    FILE_OPEN,
		CreateOptions:        0,
	}

	f, err := fs.createFile(name, create, true)
	if err != nil {
		return &os.PathError{Op: "chtimes", Path: name, Err: err}
	}

	info := &SetInfoRequest{
		FileInfoClass:         FileBasicInformation,
		AdditionalInformation: 0,
		Input: &FileBasicInformationEncoder{
			LastAccessTime: NsecToFiletime(atime.UnixNano()),
			LastWriteTime:  NsecToFiletime(mtime.UnixNano()),
		},
	}

	err = f.setInfo(info)
	if e := f.close(); err == nil {
		err = e
	}
	if err != nil {
		return &os.PathError{Op: "chtimes", Path: name, Err: err}
	}
	return nil
}

func (fs *Share) Chmod(name string, mode os.FileMode) error {
	name = normPath(name)

	if err := validatePath("chmod", name, false); err != nil {
		return err
	}

	create := &CreateRequest{
		SecurityFlags:        0,
		RequestedOplockLevel: SMB2_OPLOCK_LEVEL_NONE,
		ImpersonationLevel:   Impersonation,
		SmbCreateFlags:       0,
		DesiredAccess:        FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES,
		FileAttributes:       FILE_ATTRIBUTE_NORMAL,
		ShareAccess:          FILE_SHARE_READ | FILE_SHARE_WRITE,
		CreateDisposition:    FILE_OPEN,
		CreateOptions:        0,
	}

	f, err := fs.createFile(name, create, true)
	if err != nil {
		return &os.PathError{Op: "chmod", Path: name, Err: err}
	}

	err = f.chmod(mode)
	if e := f.close(); err == nil {
		err = e
	}
	if err != nil {
		return &os.PathError{Op: "chmod", Path: name, Err: err}
	}
	return nil
}

func (fs *Share) ReadDir(dirname string) ([]os.FileInfo, error) {
	f, err := fs.Open(dirname)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	fis, err := f.Readdir(-1)
	if err != nil {
		return nil, err
	}

	sort.Slice(fis, func(i, j int) bool { return fis[i].Name() < fis[j].Name() })

	return fis, nil
}

const (
	intSize = 32 << (^uint(0) >> 63) // 32 or 64
	maxInt  = 1<<(intSize-1) - 1
)

func (fs *Share) ReadFile(filename string) ([]byte, error) {
	f, err := fs.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	size64 := f.fileStat.Size() + 1 // one byte for final read at EOF

	var size int

	if size64 <= maxInt {
		size = int(size64)

		// If a file claims a small size, read at least 512 bytes.
		// In particular, files in Linux's /proc claim size 0 but
		// then do not work right if read in small pieces,
		// so an initial read of 1 byte would not work correctly.
		if size < 512 {
			size = 512
		}
	} else {
		size = maxInt
	}

	data := make([]byte, 0, size)
	for {
		if len(data) >= cap(data) {
			d := append(data[:cap(data)], 0)
			data = d[:len(data)]
		}
		n, err := f.Read(data[len(data):cap(data)])
		data = data[:len(data)+n]
		if err != nil {
			if err == io.EOF {
				err = nil
			}
			return data, err
		}
	}
}

func (fs *Share) WriteFile(filename string, data []byte, perm os.FileMode) error {
	f, err := fs.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}

	_, err = f.Write(data)
	if err1 := f.Close(); err == nil {
		err = err1
	}

	return err
}

func (fs *Share) Statfs(name string) (FileFsInfo, error) {
	name = normPath(name)

	if err := validatePath("statfs", name, false); err != nil {
		return nil, err
	}

	create := &CreateRequest{
		SecurityFlags:        0,
		RequestedOplockLevel: SMB2_OPLOCK_LEVEL_NONE,
		ImpersonationLevel:   Impersonation,
		SmbCreateFlags:       0,
		DesiredAccess:        FILE_READ_ATTRIBUTES,
		FileAttributes:       FILE_ATTRIBUTE_NORMAL,
		ShareAccess:          FILE_SHARE_READ | FILE_SHARE_WRITE,
		CreateDisposition:    FILE_OPEN,
		CreateOptions:        FILE_DIRECTORY_FILE,
	}

	f, err := fs.createFile(name, create, true)
	if err != nil {
		return nil, &os.PathError{Op: "statfs", Path: name, Err: err}
	}

	fi, err := f.statfs()
	if e := f.close(); err == nil {
		err = e
	}
	if err != nil {
		return nil, &os.PathError{Op: "statfs", Path: name, Err: err}
	}
	return fi, nil
}

func (fs *Share) createFile(name string, req *CreateRequest, followSymlinks bool) (f *File, err error) {
	if followSymlinks {
		return fs.createFileRec(name, req)
	}

	var responded bool
	req.CreditCharge, _, err = fs.loanCredit(0)
	defer func() {
		if err != nil && !responded {
			fs.chargeCredit(req.CreditCharge)
		}
	}()
	if err != nil {
		return nil, err
	}

	req.Name = name

	res, responded, err := fs.sendRecvResponded(SMB2_CREATE, req)
	if err != nil {
		return nil, err
	}

	r := CreateResponseDecoder(res)
	if r.IsInvalid() {
		return nil, &InvalidResponseError{"broken create response format"}
	}

	f = fs.newFile(r, name)

	return f, nil
}

func (fs *Share) createFileRec(name string, req *CreateRequest) (f *File, err error) {
	for i := 0; i < clientMaxSymlinkDepth; i++ {
		// creditCharge and responded are per iteration, so that each loan is
		// returned - or not - on its own merits. A later iteration failing must
		// not make an earlier one give its credits back a second time.
		var creditCharge uint16
		var responded bool

		creditCharge, _, err = fs.loanCredit(0)
		req.CreditCharge = creditCharge
		defer func() {
			if err != nil && !responded {
				fs.chargeCredit(creditCharge)
			}
		}()
		if err != nil {
			return nil, err
		}

		req.Name = name

		res, responded, err := fs.sendRecvResponded(SMB2_CREATE, req)
		if err != nil {
			if rerr, ok := err.(*ResponseError); ok && NtStatus(rerr.Code) == STATUS_STOPPED_ON_SYMLINK {
				if len(rerr.data) > 0 {
					name, err = evalSymlinkError(req.Name, rerr.data[0])
					if err != nil {
						return nil, err
					}
					continue
				}
			}
			return nil, err
		}

		r := CreateResponseDecoder(res)
		if r.IsInvalid() {
			return nil, &InvalidResponseError{"broken create response format"}
		}

		f = fs.newFile(r, name)

		return f, nil
	}

	return nil, &InternalError{"Too many levels of symbolic links"}
}

func evalSymlinkError(name string, errData []byte) (string, error) {
	d := SymbolicLinkErrorResponseDecoder(errData)
	if d.IsInvalid() {
		return "", &InvalidResponseError{"broken symbolic link error response format"}
	}

	ud, u := d.SplitUnparsedPath(name)
	if ud == "" && u == "" {
		return "", &InvalidResponseError{"broken symbolic link error response format"}
	}

	target := d.SubstituteName()

	switch {
	case strings.HasPrefix(target, `\??\UNC\`):
		target = `\\` + target[8:]
	case strings.HasPrefix(target, `\??\`):
		target = target[4:]
	}

	if d.Flags()&SYMLINK_FLAG_RELATIVE == 0 {
		return target + u, nil
	}

	return dir(ud) + target + u, nil
}

func (fs *Share) sendRecv(cmd uint16, req Packet) (res []byte, err error) {
	res, _, err = fs.sendRecvResponded(cmd, req)
	return res, err
}

// sendRecvResponded behaves like sendRecv and additionally reports whether a
// response packet came back.
//
// It exists for the credit accounting. conn.tryHandle charges the credits the
// server granted the moment it hands a response over, and only then - the path
// that sets rr.err instead charges nothing. A caller that returns its loan when
// the call fails must therefore skip that return once a response arrived, or
// the credits go back twice and the client ends up believing it holds credits
// the server never granted. Every error accept reports comes from a response
// that was already charged.
func (fs *Share) sendRecvResponded(cmd uint16, req Packet) (res []byte, responded bool, err error) {
	rr, err := fs.send(req, fs.ctx)
	if err != nil {
		return nil, false, err
	}

	pkt, err := fs.recv(rr)
	if err != nil {
		return nil, false, err
	}

	res, err = accept(cmd, pkt)

	return res, true, err
}

func (fs *Share) loanCredit(payloadSize int) (creditCharge uint16, grantedPayloadSize int, err error) {
	return fs.session.conn.loanCredit(payloadSize, fs.ctx)
}

// checkCreditGrant reports whether the payload a request has to send fits in
// what the granted credits cover. loanCredit hands out a partial charge when the
// credit balance is short, and MS-SMB2 3.3.5.2.5 has the server fail a request
// whose CreditCharge does not cover the payload it declares instead of queueing
// it. Response buffers can be shrunk to the grant, sendSize cannot.
func checkCreditGrant(granted, sendSize int) error {
	if granted < sendSize {
		return &CreditError{Granted: granted, Requested: sendSize}
	}
	return nil
}

// isBufferTooSmall reports whether the server rejected a query because the
// response did not fit in the buffer the request offered.
func isBufferTooSmall(err error) bool {
	rerr, ok := err.(*ResponseError)
	if !ok {
		return false
	}

	switch NtStatus(rerr.Code) {
	case STATUS_BUFFER_TOO_SMALL, STATUS_BUFFER_OVERFLOW, STATUS_INFO_LENGTH_MISMATCH:
		return true
	}

	return false
}

type File struct {
	fs          *Share
	fd          *FileId
	name        string
	fileStat    *FileStat
	dirents     []os.FileInfo
	noMoreFiles bool

	offset int64

	// id orders the offset locks when a copy holds two handles; see
	// lockOffsets. newFile assigns it, so no two handles share one.
	id uint64

	m sync.Mutex
}

var fileSeq atomic.Uint64

func (f *File) Close() error {
	if f == nil {
		return os.ErrInvalid
	}

	err := f.close()
	if err != nil {
		return &os.PathError{Op: "close", Path: f.name, Err: err}
	}
	return nil
}

func (f *File) close() error {
	if f == nil || f.fd == nil {
		return os.ErrInvalid
	}

	req := &CloseRequest{
		Flags: 0,
	}

	req.CreditCharge = 1

	req.FileId = f.fd

	res, err := f.sendRecv(SMB2_CLOSE, req)
	if err != nil {
		return err
	}

	r := CloseResponseDecoder(res)
	if r.IsInvalid() {
		return &InvalidResponseError{"broken close response format"}
	}

	f.fd = nil

	runtime.SetFinalizer(f, nil)

	return nil
}

func (f *File) remove() error {
	info := &SetInfoRequest{
		FileInfoClass:         FileDispositionInformation,
		AdditionalInformation: 0,
		Input: &FileDispositionInformationEncoder{
			DeletePending: 1,
		},
	}

	err := f.setInfo(info)
	if err != nil {
		return err
	}
	return nil
}

func (f *File) Name() string {
	return f.name
}

func (f *File) Read(b []byte) (n int, err error) {
	f.m.Lock()
	defer f.m.Unlock()

	off, err := f.seek(0, io.SeekCurrent)
	if err != nil {
		return -1, &os.PathError{Op: "read", Path: f.name, Err: err}
	}

	n, err = f.readAt(b, off)
	if n != 0 {
		if _, e := f.seek(off+int64(n), io.SeekStart); err == nil {
			err = e
		}
	}
	if err != nil {
		if err, ok := err.(*ResponseError); ok && NtStatus(err.Code) == STATUS_END_OF_FILE {
			return n, io.EOF
		}
		return n, &os.PathError{Op: "read", Path: f.name, Err: err}
	}

	return
}

// ReadAt implements io.ReaderAt.
func (f *File) ReadAt(b []byte, off int64) (n int, err error) {
	if off < 0 {
		return -1, os.ErrInvalid
	}

	n, err = f.readAt(b, off)
	if err != nil {
		if err, ok := err.(*ResponseError); ok && NtStatus(err.Code) == STATUS_END_OF_FILE {
			return n, io.EOF
		}
		return n, &os.PathError{Op: "read", Path: f.name, Err: err}
	}
	return n, nil
}

const winMaxPayloadSize = 1024 * 1024 // windows system don't accept more than 1M bytes request even though they tell us maxXXXSize > 1M
const singleCreditMaxPayloadSize = 64 * 1024

func (f *File) maxReadSize() int {
	size := int(f.fs.maxReadSize)
	if size > winMaxPayloadSize {
		size = winMaxPayloadSize
	}
	if f.fs.conn.capabilities&SMB2_GLOBAL_CAP_LARGE_MTU == 0 {
		if size > singleCreditMaxPayloadSize {
			size = singleCreditMaxPayloadSize
		}
	}
	return size
}

func (f *File) maxWriteSize() int {
	size := int(f.fs.maxWriteSize)
	if size > winMaxPayloadSize {
		size = winMaxPayloadSize
	}
	if f.fs.conn.capabilities&SMB2_GLOBAL_CAP_LARGE_MTU == 0 {
		if size > singleCreditMaxPayloadSize {
			size = singleCreditMaxPayloadSize
		}
	}
	return size
}

func (f *File) maxTransactSize() int {
	size := int(f.fs.maxTransactSize)
	if size > winMaxPayloadSize {
		size = winMaxPayloadSize
	}
	if f.fs.conn.capabilities&SMB2_GLOBAL_CAP_LARGE_MTU == 0 {
		if size > singleCreditMaxPayloadSize {
			size = singleCreditMaxPayloadSize
		}
	}
	return size
}

func (f *File) readAt(b []byte, off int64) (n int, err error) {
	if off < 0 {
		return -1, os.ErrInvalid
	}

	maxReadSize := f.maxReadSize()

	for {
		switch {
		case len(b)-n == 0:
			return n, nil
		case len(b)-n <= maxReadSize:
			bs, isEOF, err := f.readAtChunk(len(b)-n, int64(n)+off)
			if err != nil {
				if err, ok := err.(*ResponseError); ok && NtStatus(err.Code) == STATUS_END_OF_FILE && n != 0 {
					return n, nil
				}
				return 0, err
			}

			n += copy(b[n:], bs)

			if isEOF {
				return n, nil
			}
		default:
			bs, isEOF, err := f.readAtChunk(maxReadSize, int64(n)+off)
			if err != nil {
				if err, ok := err.(*ResponseError); ok && NtStatus(err.Code) == STATUS_END_OF_FILE && n != 0 {
					return n, nil
				}
				return 0, err
			}

			n += copy(b[n:], bs)

			if isEOF {
				return n, nil
			}
		}
	}
}

func (f *File) readAtChunk(n int, off int64) (bs []byte, isEOF bool, err error) {
	var responded bool
	creditCharge, m, err := f.fs.loanCredit(n)
	defer func() {
		if err != nil && !responded {
			f.fs.chargeCredit(creditCharge)
		}
	}()
	if err != nil {
		return nil, false, err
	}

	req := &ReadRequest{
		Padding:         0,
		Flags:           0,
		Length:          uint32(m),
		Offset:          uint64(off),
		MinimumCount:    1, // for returning EOF
		Channel:         0,
		RemainingBytes:  0,
		ReadChannelInfo: nil,
	}

	req.FileId = f.fd

	req.CreditCharge = creditCharge

	res, responded, err := f.sendRecvResponded(SMB2_READ, req)
	if err != nil {
		return nil, false, err
	}

	r := ReadResponseDecoder(res)
	if r.IsInvalid() {
		return nil, false, &InvalidResponseError{"broken read response format"}
	}

	bs = r.Data()

	return bs, len(bs) < m, nil
}

func (f *File) Readdir(n int) (fi []os.FileInfo, err error) {
	f.m.Lock()
	defer f.m.Unlock()

	if !f.noMoreFiles {
		if f.dirents == nil {
			f.dirents = []os.FileInfo{}
		}
		for n <= 0 || n > len(f.dirents) {
			dirents, err := f.readdir("*")
			if len(dirents) > 0 {
				f.dirents = append(f.dirents, dirents...)
			}
			if err != nil {
				if err, ok := err.(*ResponseError); ok && NtStatus(err.Code) == STATUS_NO_MORE_FILES {
					f.noMoreFiles = true
					break
				}
				return nil, &os.PathError{Op: "readdir", Path: f.name, Err: err}
			}
		}
	}

	fi = f.dirents

	if n > 0 {
		if len(fi) == 0 {
			return fi, io.EOF
		}

		if len(fi) < n {
			f.dirents = []os.FileInfo{}
			return fi, nil
		}

		f.dirents = fi[n:]
		return fi[:n], nil

	}

	f.dirents = []os.FileInfo{}

	return fi, nil
}

func (f *File) Readdirnames(n int) (names []string, err error) {
	fi, err := f.Readdir(n)
	if err != nil {
		return nil, err
	}

	names = make([]string, len(fi))

	for i, st := range fi {
		names[i] = st.Name()
	}

	return names, nil
}

// Seek implements io.Seeker.
func (f *File) Seek(offset int64, whence int) (ret int64, err error) {
	f.m.Lock()
	defer f.m.Unlock()

	ret, err = f.seek(offset, whence)
	if err != nil {
		return ret, &os.PathError{Op: "seek", Path: f.name, Err: err}
	}
	return ret, nil
}

func (f *File) seek(offset int64, whence int) (ret int64, err error) {
	switch whence {
	case io.SeekStart:
		f.offset = offset
	case io.SeekCurrent:
		f.offset += offset
	case io.SeekEnd:
		req := &QueryInfoRequest{
			InfoType:              SMB2_0_INFO_FILE,
			FileInfoClass:         FileStandardInformation,
			AdditionalInformation: 0,
			Flags:                 0,
			OutputBufferLength:    24,
		}

		infoBytes, err := f.queryInfo(req)
		if err != nil {
			return -1, err
		}

		info := FileStandardInformationDecoder(infoBytes)
		if info.IsInvalid() {
			return -1, &InvalidResponseError{"broken query info response format"}
		}

		f.offset = offset + info.EndOfFile()
	default:
		return -1, os.ErrInvalid
	}

	return f.offset, nil
}

func (f *File) Stat() (os.FileInfo, error) {
	fi, err := f.stat()
	if err != nil {
		return nil, &os.PathError{Op: "stat", Path: f.name, Err: err}
	}
	return fi, nil
}

func (f *File) stat() (os.FileInfo, error) {
	req := &QueryInfoRequest{
		InfoType:              SMB2_0_INFO_FILE,
		FileInfoClass:         FileAllInformation,
		AdditionalInformation: 0,
		Flags:                 0,
		OutputBufferLength:    uint32(f.maxTransactSize()),
	}

	infoBytes, err := f.queryInfo(req)
	if err != nil {
		return nil, err
	}

	info := FileAllInformationDecoder(infoBytes)
	if info.IsInvalid() {
		return nil, &InvalidResponseError{"broken query info response format"}
	}

	basic := info.BasicInformation()
	std := info.StandardInformation()

	return &FileStat{
		CreationTime:   time.Unix(0, basic.CreationTime().Nanoseconds()),
		LastAccessTime: time.Unix(0, basic.LastAccessTime().Nanoseconds()),
		LastWriteTime:  time.Unix(0, basic.LastWriteTime().Nanoseconds()),
		ChangeTime:     time.Unix(0, basic.ChangeTime().Nanoseconds()),
		EndOfFile:      std.EndOfFile(),
		AllocationSize: std.AllocationSize(),
		FileAttributes: basic.FileAttributes(),
		FileName:       base(f.name),
	}, nil
}

func (f *File) Statfs() (FileFsInfo, error) {
	fi, err := f.statfs()
	if err != nil {
		return nil, &os.PathError{Op: "statfs", Path: f.name, Err: err}
	}
	return fi, nil
}

type FileFsInfo interface {
	BlockSize() uint64
	FragmentSize() uint64
	TotalBlockCount() uint64
	FreeBlockCount() uint64
	AvailableBlockCount() uint64
}

type fileFsFullSizeInformation struct {
	TotalAllocationUnits           int64
	CallerAvailableAllocationUnits int64
	ActualAvailableAllocationUnits int64
	SectorsPerAllocationUnit       uint32
	BytesPerSector                 uint32
}

func (fi *fileFsFullSizeInformation) BlockSize() uint64 {
	return uint64(fi.BytesPerSector)
}

func (fi *fileFsFullSizeInformation) FragmentSize() uint64 {
	return uint64(fi.SectorsPerAllocationUnit)
}

func (fi *fileFsFullSizeInformation) TotalBlockCount() uint64 {
	return uint64(fi.TotalAllocationUnits)
}

func (fi *fileFsFullSizeInformation) FreeBlockCount() uint64 {
	return uint64(fi.ActualAvailableAllocationUnits)
}

func (fi *fileFsFullSizeInformation) AvailableBlockCount() uint64 {
	return uint64(fi.CallerAvailableAllocationUnits)
}

func (f *File) statfs() (FileFsInfo, error) {
	req := &QueryInfoRequest{
		InfoType:              SMB2_0_INFO_FILESYSTEM,
		FileInfoClass:         FileFsFullSizeInformation,
		AdditionalInformation: 0,
		Flags:                 0,
		OutputBufferLength:    32,
	}

	infoBytes, err := f.queryInfo(req)
	if err != nil {
		return nil, err
	}

	info := FileFsFullSizeInformationDecoder(infoBytes)
	if info.IsInvalid() {
		return nil, &InvalidResponseError{"broken query info response format"}
	}

	return &fileFsFullSizeInformation{
		TotalAllocationUnits:           info.TotalAllocationUnits(),
		CallerAvailableAllocationUnits: info.CallerAvailableAllocationUnits(),
		ActualAvailableAllocationUnits: info.ActualAvailableAllocationUnits(),
		SectorsPerAllocationUnit:       info.SectorsPerAllocationUnit(),
		BytesPerSector:                 info.BytesPerSector(),
	}, nil
}

func (f *File) Sync() (err error) {
	req := new(FlushRequest)
	req.FileId = f.fd

	var responded bool
	req.CreditCharge, _, err = f.fs.loanCredit(0)
	defer func() {
		if err != nil && !responded {
			f.fs.chargeCredit(req.CreditCharge)
		}
	}()
	if err != nil {
		return &os.PathError{Op: "sync", Path: f.name, Err: err}
	}

	res, responded, err := f.sendRecvResponded(SMB2_FLUSH, req)
	if err != nil {
		return &os.PathError{Op: "sync", Path: f.name, Err: err}
	}

	r := FlushResponseDecoder(res)
	if r.IsInvalid() {
		return &os.PathError{Op: "sync", Path: f.name, Err: &InvalidResponseError{"broken flush response format"}}
	}

	return nil
}

func (f *File) Truncate(size int64) error {
	if size < 0 {
		return os.ErrInvalid
	}

	err := f.truncate(size)
	if err != nil {
		return &os.PathError{Op: "truncate", Path: f.name, Err: err}
	}
	return nil
}

func (f *File) truncate(size int64) error {
	info := &SetInfoRequest{
		FileInfoClass:         FileEndOfFileInformation,
		AdditionalInformation: 0,
		Input: &FileEndOfFileInformationEncoder{
			EndOfFile: size,
		},
	}

	err := f.setInfo(info)
	if err != nil {
		return err
	}
	return nil
}

func (f *File) Chmod(mode os.FileMode) error {
	err := f.chmod(mode)
	if err != nil {
		return &os.PathError{Op: "chmod", Path: f.name, Err: err}
	}
	return nil
}

func (f *File) chmod(mode os.FileMode) error {
	req := &QueryInfoRequest{
		InfoType:              SMB2_0_INFO_FILE,
		FileInfoClass:         FileBasicInformation,
		AdditionalInformation: 0,
		Flags:                 0,
		OutputBufferLength:    40,
	}

	infoBytes, err := f.queryInfo(req)
	if err != nil {
		return err
	}

	base := FileBasicInformationDecoder(infoBytes)
	if base.IsInvalid() {
		return &InvalidResponseError{"broken query info response format"}
	}

	attrs := base.FileAttributes()

	if mode&0200 != 0 {
		attrs &^= FILE_ATTRIBUTE_READONLY
	} else {
		attrs |= FILE_ATTRIBUTE_READONLY
	}

	info := &SetInfoRequest{
		FileInfoClass:         FileBasicInformation,
		AdditionalInformation: 0,
		Input: &FileBasicInformationEncoder{
			FileAttributes: attrs,
		},
	}

	err = f.setInfo(info)
	if err != nil {
		return err
	}
	return nil
}

func (f *File) Write(b []byte) (n int, err error) {
	f.m.Lock()
	defer f.m.Unlock()

	off, err := f.seek(0, io.SeekCurrent)
	if err != nil {
		return -1, &os.PathError{Op: "write", Path: f.name, Err: err}
	}

	n, err = f.writeAt(b, off)
	if n != 0 {
		if _, e := f.seek(off+int64(n), io.SeekStart); err == nil {
			err = e
		}
	}
	if err != nil {
		return n, &os.PathError{Op: "write", Path: f.name, Err: err}
	}

	return n, nil
}

// WriteAt implements io.WriterAt.
func (f *File) WriteAt(b []byte, off int64) (n int, err error) {
	n, err = f.writeAt(b, off)
	if err != nil {
		return n, &os.PathError{Op: "write", Path: f.name, Err: err}
	}
	return n, nil
}

func (f *File) writeAt(b []byte, off int64) (n int, err error) {
	if off < 0 {
		return -1, os.ErrInvalid
	}

	if len(b) == 0 {
		return 0, nil
	}

	maxWriteSize := f.maxWriteSize()

	for {
		switch {
		case len(b)-n == 0:
			return n, nil
		case len(b)-n <= maxWriteSize:
			m, err := f.writeAtChunk(b[n:], int64(n)+off)
			if err != nil {
				return -1, err
			}

			n += m
		default:
			m, err := f.writeAtChunk(b[n:n+maxWriteSize], int64(n)+off)
			if err != nil {
				return -1, err
			}

			n += m
		}
	}
}

// writeAt allows partial write
func (f *File) writeAtChunk(b []byte, off int64) (n int, err error) {
	var responded bool
	creditCharge, m, err := f.fs.loanCredit(len(b))
	defer func() {
		if err != nil && !responded {
			f.fs.chargeCredit(creditCharge)
		}
	}()
	if err != nil {
		return 0, err
	}

	req := &WriteRequest{
		Flags:            0,
		Channel:          0,
		RemainingBytes:   0,
		Offset:           uint64(off),
		WriteChannelInfo: nil,
		Data:             b[:m],
	}

	req.FileId = f.fd

	req.CreditCharge = creditCharge

	res, responded, err := f.sendRecvResponded(SMB2_WRITE, req)
	if err != nil {
		return 0, err
	}

	r := WriteResponseDecoder(res)
	if r.IsInvalid() {
		return 0, &InvalidResponseError{"broken write response format"}
	}

	return int(r.Count()), nil
}

func copyBuffer(r io.Reader, w io.Writer, buf []byte) (n int64, err error) {
	for {
		nr, er := r.Read(buf)
		if nr > 0 {
			nw, ew := w.Write(buf[:nr])
			if nw > 0 {
				n += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}
	return
}

// copychunkLimits bound one FSCTL_SRV_COPYCHUNK request: how many chunks it may
// carry, how long each of them may be, and how much they may add up to.
type copychunkLimits struct {
	chunks    uint32
	chunkSize uint32
	totalSize uint32
}

// defaultCopychunkLimits are what MS-SMB2 3.3.5.15.6 tells a client to assume
// before the server has said otherwise. A server wanting less rejects the
// request and returns its own; see copychunkLimitsFrom.
var defaultCopychunkLimits = copychunkLimits{
	chunks:    16,
	chunkSize: 1024 * 1024,
	totalSize: 16 * 1024 * 1024,
}

// usable reports whether the limits leave room for any progress at all. A zero
// in any of the three would plan an empty request forever.
func (l copychunkLimits) usable() bool {
	return l.chunks > 0 && l.chunkSize > 0 && l.totalSize > 0
}

// clamp bounds the limits to the descriptors one request can carry. The count
// is server-controlled and reaches planCopychunks before ioctl can measure the
// request: an advertised 0xFFFFFFFF with a one-byte chunk size would size the
// allocation by the length of the copy rather than by the protocol.
func (l copychunkLimits) clamp(maxChunks uint32) copychunkLimits {
	if maxChunks == 0 {
		maxChunks = 1
	}
	if l.chunks > maxChunks {
		l.chunks = maxChunks
	}
	return l
}

// copychunkLimitsFrom reads the limits a server attached to a rejected request.
// The SRV_COPYCHUNK_RESPONSE that comes back with STATUS_INVALID_PARAMETER
// carries maxima in the fields that otherwise count what was written
// (MS-SMB2 2.2.32.1).
func copychunkLimitsFrom(output []byte) (copychunkLimits, bool) {
	c := SrvCopychunkResponseDecoder(output)
	if c.IsInvalid() {
		return copychunkLimits{}, false
	}

	l := copychunkLimits{
		chunks:    c.ChunksWritten(),
		chunkSize: c.ChunksBytesWritten(),
		totalSize: c.TotalBytesWritten(),
	}
	return l, l.usable()
}

// planCopychunks lays out one request's worth of chunks, copying the bytes at
// srcOff to dstOff, and returns how many bytes they cover.
//
// Both offsets are absolute and neither is remembered, which is why the walk
// across requests is copychunkPlanner's job and not this function's.
func planCopychunks(srcOff, dstOff, remains int64, l copychunkLimits) ([]*SrvCopychunk, int64) {
	budget := remains
	if int64(l.totalSize) < budget {
		budget = int64(l.totalSize)
	}

	var (
		chunks  []*SrvCopychunk
		planned int64
	)
	for planned < budget && uint32(len(chunks)) < l.chunks {
		length := budget - planned
		if int64(l.chunkSize) < length {
			length = int64(l.chunkSize)
		}
		chunks = append(chunks, &SrvCopychunk{
			SourceOffset: srcOff + planned,
			TargetOffset: dstOff + planned,
			Length:       uint32(length),
		})
		planned += length
	}

	return chunks, planned
}

// copychunkPlanner walks one copy across as many FSCTL_SRV_COPYCHUNK requests
// as the server's limits make necessary. It is what remembers where the last
// request got to -- a plan that forgets that restarts at the top of the file on
// its second request, and the byte count still comes out right.
type copychunkPlanner struct {
	srcOff  int64 // where the copy started reading
	dstOff  int64 // where it started writing
	copied  int64 // bytes the server has reported written
	remains int64 // bytes not yet accounted for
	limits  copychunkLimits

	maxChunks uint32 // descriptors one request can carry
}

func newCopychunkPlanner(srcOff, dstOff, size int64, maxChunks uint32) *copychunkPlanner {
	return &copychunkPlanner{
		srcOff:    srcOff,
		dstOff:    dstOff,
		remains:   size,
		limits:    defaultCopychunkLimits.clamp(maxChunks),
		maxChunks: maxChunks,
	}
}

// done reports whether every byte has been accounted for.
func (p *copychunkPlanner) done() bool { return p.remains <= 0 }

// next lays out the request to send now, and how many bytes it covers.
func (p *copychunkPlanner) next() ([]*SrvCopychunk, int64) {
	return planCopychunks(p.srcOff+p.copied, p.dstOff+p.copied, p.remains, p.limits)
}

// narrow re-chunks what is left against the limits a server returned, bounded
// by what this client can send.
func (p *copychunkPlanner) narrow(l copychunkLimits) { p.limits = l.clamp(p.maxChunks) }

// advance records what the server reported writing for the request next laid
// out. The server may write less than was asked for, but zero would not
// terminate and more than was asked for is not a number this can copy past.
func (p *copychunkPlanner) advance(written, planned int64) error {
	if written <= 0 || written > planned {
		return &InvalidResponseError{fmt.Sprintf("srv copy chunk reported %d of %d requested bytes", written, planned)}
	}

	p.copied += written
	p.remains -= written
	return nil
}

// maxCopychunks is how many chunk descriptors one request can carry: an
// SRV_COPYCHUNK_COPY is a 32-byte header and 24 bytes per descriptor, and
// ioctl refuses a payload past the negotiated transaction size.
func (f *File) maxCopychunks() uint32 {
	room := (f.maxTransactSize() - 32) / 24
	if room < 1 {
		return 1
	}
	return uint32(room)
}

// copychunkUnsupported reports whether err says the backend cannot serve a
// copychunk at all, as opposed to failing this particular one.
func copychunkUnsupported(err error) bool {
	rerr, ok := err.(*ResponseError)
	if !ok {
		return false
	}
	switch NtStatus(rerr.Code) {
	case STATUS_NOT_SUPPORTED, STATUS_INVALID_DEVICE_REQUEST:
		return true
	}
	return false
}

// rejectedForLimits reports whether err is the rejection that carries the
// server's own limits.
func rejectedForLimits(err error) bool {
	rerr, ok := err.(*ResponseError)
	return ok && NtStatus(rerr.Code) == STATUS_INVALID_PARAMETER
}

// sameSession reports whether two handles are eligible for a server-side copy
// between them. The resume key is scoped to the session rather than to the tree
// connect, so two shares mounted on one session qualify.
func sameSession(a, b *File) bool {
	if a == nil || b == nil || a.fs == nil || b.fs == nil {
		return false
	}
	if a.fs.treeConn == nil || b.fs.treeConn == nil {
		return false
	}
	return a.fs.session == b.fs.session
}

// lockOffsets locks the offsets of both handles a copy moves and returns the
// release. Both are mutated -- the source is seeked to EOF, the destination is
// left where the copy ended -- and File's offset is only ever touched under its
// own lock.
//
// The order is by id rather than by argument, so two copies running in opposite
// directions cannot each hold the lock the other wants. Copying a handle onto
// itself is one offset and one lock; taking it twice would deadlock on a
// sync.Mutex.
func lockOffsets(a, b *File) func() {
	if a == b {
		a.m.Lock()
		return a.m.Unlock
	}

	first, second := a, b
	if b.id < a.id {
		first, second = b, a
	}

	first.m.Lock()
	second.m.Lock()
	return func() {
		second.m.Unlock()
		first.m.Unlock()
	}
}

// copyTo copies the rest of f into wf without the bytes passing through this
// process, and reports whether the pair supports that at all.
//
// supported == false leaves both handles exactly where the caller left them, so
// the same bytes can be streamed instead. Any other error may leave wf
// partially written.
func (f *File) copyTo(wf *File) (supported bool, n int64, err error) {
	defer lockOffsets(f, wf)()

	fail := func(err error) (bool, int64, error) {
		return true, -1, &os.LinkError{Op: "copy", Old: f.name, New: wf.name, Err: err}
	}

	req := &IoctlRequest{
		CtlCode:           FSCTL_SRV_REQUEST_RESUME_KEY,
		OutputOffset:      0,
		OutputCount:       0,
		MaxInputResponse:  0,
		MaxOutputResponse: 32,
		Flags:             SMB2_0_IOCTL_IS_FSCTL,
	}

	output, err := f.ioctl(req)
	if err != nil {
		if copychunkUnsupported(err) {
			return false, -1, nil
		}

		return fail(err)
	}

	sr := SrvRequestResumeKeyResponseDecoder(output)
	if sr.IsInvalid() {
		return fail(&InvalidResponseError{"broken srv request resume key response format"})
	}

	off, err := f.seek(0, io.SeekCurrent)
	if err != nil {
		return fail(err)
	}

	end, err := f.seek(0, io.SeekEnd)
	if err != nil {
		return fail(err)
	}

	woff, err := wf.seek(0, io.SeekCurrent)
	if err != nil {
		return fail(err)
	}

	// What is left of f from where the caller had it, not the whole file: a
	// partially read handle copies the rest, the way streaming it would.
	remains := end - off
	if remains <= 0 {
		// A request carrying no chunks is how MS-SMB2 3.3.5.15.6 says to ask a
		// server for its limits, and it is answered STATUS_INVALID_PARAMETER --
		// so an empty file must not be sent as one.
		return true, 0, nil
	}

	scc := &SrvCopychunkCopy{}
	copy(scc.SourceKey[:], sr.ResumeKey())

	plan := newCopychunkPlanner(off, woff, remains, wf.maxCopychunks())
	renegotiated := false

	for !plan.done() {
		chunks, planned := plan.next()
		scc.Chunks = chunks

		cReq := &IoctlRequest{
			CtlCode:           FSCTL_SRV_COPYCHUNK,
			OutputOffset:      0,
			OutputCount:       0,
			MaxInputResponse:  0,
			MaxOutputResponse: 24,
			Flags:             SMB2_0_IOCTL_IS_FSCTL,
			Input:             scc,
		}

		output, err := wf.ioctl(cReq)
		if err != nil {
			// A server that wants smaller requests says so by rejecting one and
			// returning its limits. Re-chunking against them is worth one retry;
			// a second would let a server that keeps rejecting spin here, and the
			// limits are a property of the server, not of the request.
			if !renegotiated && rejectedForLimits(err) {
				if narrowed, ok := copychunkLimitsFrom(output); ok {
					renegotiated = true
					plan.narrow(narrowed)
					continue
				}
			}

			if plan.copied == 0 && copychunkUnsupported(err) {
				// Nothing was written, so both handles can go back to where the
				// caller left them and the copy can be streamed instead.
				f.seek(off, io.SeekStart)
				wf.seek(woff, io.SeekStart)
				return false, -1, nil
			}

			return fail(err)
		}

		c := SrvCopychunkResponseDecoder(output)
		if c.IsInvalid() {
			return fail(&InvalidResponseError{"broken srv copy chunk response format"})
		}

		if err := plan.advance(int64(c.TotalBytesWritten()), planned); err != nil {
			return fail(err)
		}
	}

	// A streamed copy leaves the destination advanced by what it received; the
	// ioctl writes at an offset and moves nothing.
	if _, err := wf.seek(woff+plan.copied, io.SeekStart); err != nil {
		return fail(err)
	}

	return true, plan.copied, nil
}

// ErrServerSideCopyUnsupported reports that a pair of handles cannot be copied
// by the server: they are not on one session, or the backend rejects the ioctl.
// Nothing was copied and neither handle moved.
var ErrServerSideCopyUnsupported = errors.New("smb2: server-side copy is not supported for these files")

// ServerSideCopy copies src, from its current offset to its end, into dst at
// dst's current offset, without the bytes travelling through this process.
//
// It leaves src at EOF and dst advanced by what was written, as io.Copy would.
// ErrServerSideCopyUnsupported means the caller can stream the same bytes
// instead; on any other error dst may be partially written.
//
// ReadFrom and WriteTo do this on their own for an *File argument. This is for
// a caller holding the two handles inside wrappers of its own, where neither of
// those can recognise the pair.
func ServerSideCopy(dst, src *File) (int64, error) {
	if !sameSession(src, dst) {
		return 0, ErrServerSideCopyUnsupported
	}

	supported, n, err := src.copyTo(dst)
	if !supported {
		return 0, ErrServerSideCopyUnsupported
	}
	if err != nil {
		return 0, err
	}
	return n, nil
}

// ReadFrom implements io.ReadFrom.
// If r is an *File on the same session as f, it invokes server-side copy.
func (f *File) ReadFrom(r io.Reader) (n int64, err error) {
	rf, ok := r.(*File)
	if ok && sameSession(rf, f) {
		if supported, n, err := rf.copyTo(f); supported {
			return n, err
		}

		maxBufferSize := f.maxReadSize()
		if maxWriteSize := f.maxWriteSize(); maxWriteSize < maxBufferSize {
			maxBufferSize = maxWriteSize
		}

		return copyBuffer(r, f, make([]byte, maxBufferSize))
	}

	return copyBuffer(r, f, make([]byte, f.maxWriteSize()))
}

// WriteTo implements io.WriteTo.
// If w is an *File on the same session as f, it invokes server-side copy.
func (f *File) WriteTo(w io.Writer) (n int64, err error) {
	wf, ok := w.(*File)
	if ok && sameSession(f, wf) {
		if supported, n, err := f.copyTo(wf); supported {
			return n, err
		}

		maxBufferSize := f.maxReadSize()
		if maxWriteSize := f.maxWriteSize(); maxWriteSize < maxBufferSize {
			maxBufferSize = maxWriteSize
		}

		return copyBuffer(f, w, make([]byte, maxBufferSize))
	}

	return copyBuffer(f, w, make([]byte, f.maxReadSize()))
}

func (f *File) WriteString(s string) (n int, err error) {
	return f.Write([]byte(s))
}

func (f *File) encodeSize(e Encoder) int {
	if e == nil {
		return 0
	}
	return e.Size()
}

func (f *File) ioctl(req *IoctlRequest) (output []byte, err error) {
	payloadSize := f.encodeSize(req.Input) + int(req.OutputCount)
	if payloadSize < int(req.MaxOutputResponse+req.MaxInputResponse) {
		payloadSize = int(req.MaxOutputResponse + req.MaxInputResponse)
	}

	if f.maxTransactSize() < payloadSize {
		return nil, &InternalError{fmt.Sprintf("payload size %d exceeds max transact size %d", payloadSize, f.maxTransactSize())}
	}

	var granted int
	var responded bool
	req.CreditCharge, granted, err = f.fs.loanCredit(payloadSize)
	defer func() {
		if err != nil && !responded {
			f.fs.chargeCredit(req.CreditCharge)
		}
	}()
	if err != nil {
		return nil, err
	}

	if granted < payloadSize {
		// The output allowance is what is left of the grant once the payload
		// being sent and MaxInputResponse are accounted for. MaxInputResponse
		// has to be part of the floor so that subtracting it below cannot
		// underflow, and the grant has to leave at least one byte for output -
		// a request offering no room for a response is pointless.
		floor := f.encodeSize(req.Input) + int(req.OutputCount)
		if int(req.MaxInputResponse) >= floor {
			floor = int(req.MaxInputResponse) + 1
		}
		if err = checkCreditGrant(granted, floor); err != nil {
			return nil, err
		}
		req.MaxOutputResponse = uint32(granted - int(req.MaxInputResponse))
	}

	req.FileId = f.fd

	res, responded, err := f.sendRecvResponded(SMB2_IOCTL, req)
	if err != nil {
		r := IoctlResponseDecoder(res)
		if r.IsInvalid() {
			return nil, err
		}
		return r.Output(), err
	}

	r := IoctlResponseDecoder(res)
	if r.IsInvalid() {
		return nil, &InvalidResponseError{"broken ioctl response format"}
	}

	return r.Output(), nil
}

func (f *File) readdir(pattern string) (fi []os.FileInfo, err error) {
	req := &QueryDirectoryRequest{
		FileInfoClass:      FileDirectoryInformation,
		Flags:              0,
		FileIndex:          0,
		OutputBufferLength: uint32(f.maxTransactSize()),
		FileName:           pattern,
	}

	payloadSize := int(req.OutputBufferLength)

	if f.maxTransactSize() < payloadSize {
		return nil, &InternalError{fmt.Sprintf("payload size %d exceeds max transact size %d", payloadSize, f.maxTransactSize())}
	}

	var granted int
	var responded bool
	req.CreditCharge, granted, err = f.fs.loanCredit(payloadSize)
	defer func() {
		if err != nil && !responded {
			f.fs.chargeCredit(req.CreditCharge)
		}
	}()
	if err != nil {
		return nil, err
	}

	// A shorter output buffer just means fewer entries per round trip; the
	// caller reads the rest on the next readdir.
	if granted < payloadSize {
		req.OutputBufferLength = uint32(granted)
	}

	req.FileId = f.fd

	res, responded, err := f.sendRecvResponded(SMB2_QUERY_DIRECTORY, req)
	if err != nil {
		return nil, err
	}

	r := QueryDirectoryResponseDecoder(res)
	if r.IsInvalid() {
		return nil, &InvalidResponseError{"broken query directory response format"}
	}

	return parseDirectoryEntries(r.OutputBuffer())
}

// parseDirectoryEntries walks the FILE_DIRECTORY_INFORMATION chain of a
// QUERY_DIRECTORY response. Split out of readdir so the bounds check on the
// server-controlled NextEntryOffset can be tested without a server.
func parseDirectoryEntries(output []byte) (fi []os.FileInfo, err error) {
	for {
		info := FileDirectoryInformationDecoder(output)
		if info.IsInvalid() {
			return nil, &InvalidResponseError{"broken query directory response format"}
		}

		name := info.FileName()

		if name != "." && name != ".." {
			fi = append(fi, &FileStat{
				CreationTime:   time.Unix(0, info.CreationTime().Nanoseconds()),
				LastAccessTime: time.Unix(0, info.LastAccessTime().Nanoseconds()),
				LastWriteTime:  time.Unix(0, info.LastWriteTime().Nanoseconds()),
				ChangeTime:     time.Unix(0, info.ChangeTime().Nanoseconds()),
				EndOfFile:      info.EndOfFile(),
				AllocationSize: info.AllocationSize(),
				FileAttributes: info.FileAttributes(),
				FileName:       name,
			})
		}

		next := info.NextEntryOffset()
		if next == 0 {
			return fi, nil
		}

		// Server-controlled; slicing past the end would panic the caller.
		// The 8-byte alignment MS-FSCC 2.4.10 requires also puts the next
		// entry at or past the end of this one, so an offset that does not
		// advance is malformed.
		if uint64(next) < 64+uint64(info.FileNameLength()) || uint64(next) >= uint64(len(output)) {
			return nil, &InvalidResponseError{"broken query directory response format"}
		}

		output = output[next:]
	}
}

func (f *File) queryInfo(req *QueryInfoRequest) (infoBytes []byte, err error) {
	payloadSize := f.encodeSize(req.Input)
	if payloadSize < int(req.OutputBufferLength) {
		payloadSize = int(req.OutputBufferLength)
	}

	if f.maxTransactSize() < payloadSize {
		return nil, &InternalError{fmt.Sprintf("payload size %d exceeds max transact size %d", payloadSize, f.maxTransactSize())}
	}

	outputBufferLength := req.OutputBufferLength

	infoBytes, err = f.queryInfoOnce(req, payloadSize)

	// Unlike readdir, which just gets fewer entries per round trip, a query cut
	// short by a partial credit grant has no way to pick up the rest. If the
	// response did not fit in the shrunken buffer, try once more at the size
	// originally asked for - the balance recovers as outstanding requests
	// complete, so a second attempt usually gets a full grant.
	if err != nil && req.OutputBufferLength < outputBufferLength && isBufferTooSmall(err) {
		req.OutputBufferLength = outputBufferLength

		infoBytes, err = f.queryInfoOnce(req, payloadSize)
	}

	return infoBytes, err
}

func (f *File) queryInfoOnce(req *QueryInfoRequest, payloadSize int) (infoBytes []byte, err error) {
	var granted int
	var responded bool
	req.CreditCharge, granted, err = f.fs.loanCredit(payloadSize)
	defer func() {
		if err != nil && !responded {
			f.fs.chargeCredit(req.CreditCharge)
		}
	}()
	if err != nil {
		return nil, err
	}

	if granted < payloadSize {
		if err = checkCreditGrant(granted, f.encodeSize(req.Input)); err != nil {
			return nil, err
		}
		req.OutputBufferLength = uint32(granted)
	}

	req.FileId = f.fd

	res, responded, err := f.sendRecvResponded(SMB2_QUERY_INFO, req)
	if err != nil {
		return nil, err
	}

	r := QueryInfoResponseDecoder(res)
	if r.IsInvalid() {
		return nil, &InvalidResponseError{"broken query info response format"}
	}

	return r.OutputBuffer(), nil
}

func (f *File) setInfo(req *SetInfoRequest) (err error) {
	payloadSize := f.encodeSize(req.Input)

	if f.maxTransactSize() < payloadSize {
		return &InternalError{fmt.Sprintf("payload size %d exceeds max transact size %d", payloadSize, f.maxTransactSize())}
	}

	var granted int
	var responded bool
	req.CreditCharge, granted, err = f.fs.loanCredit(payloadSize)
	defer func() {
		if err != nil && !responded {
			f.fs.chargeCredit(req.CreditCharge)
		}
	}()
	if err != nil {
		return err
	}

	// Set info carries no response buffer, so there is nothing to shrink and
	// the whole payload has to fit the grant. The check is unguarded on purpose:
	// a complete grant returns payloadSize and satisfies it trivially, so the
	// "granted < payloadSize" guard the other paths need would be noise here.
	if err = checkCreditGrant(granted, payloadSize); err != nil {
		return err
	}

	req.FileId = f.fd

	req.InfoType = SMB2_0_INFO_FILE

	res, responded, err := f.sendRecvResponded(SMB2_SET_INFO, req)
	if err != nil {
		return err
	}

	r := SetInfoResponseDecoder(res)
	if r.IsInvalid() {
		return &InvalidResponseError{"broken set info response format"}
	}

	return nil
}

func (f *File) sendRecv(cmd uint16, req Packet) (res []byte, err error) {
	return f.fs.sendRecv(cmd, req)
}

func (f *File) sendRecvResponded(cmd uint16, req Packet) (res []byte, responded bool, err error) {
	return f.fs.sendRecvResponded(cmd, req)
}

type FileStat struct {
	CreationTime   time.Time
	LastAccessTime time.Time
	LastWriteTime  time.Time
	ChangeTime     time.Time
	EndOfFile      int64
	AllocationSize int64
	FileAttributes uint32
	FileName       string
}

func (fs *FileStat) Name() string {
	return fs.FileName
}

func (fs *FileStat) Size() int64 {
	return fs.EndOfFile
}

func (fs *FileStat) Mode() os.FileMode {
	var m os.FileMode

	if fs.FileAttributes&FILE_ATTRIBUTE_DIRECTORY != 0 {
		m |= os.ModeDir | 0111
	}

	if fs.FileAttributes&FILE_ATTRIBUTE_READONLY != 0 {
		m |= 0444
	} else {
		m |= 0666
	}

	if fs.FileAttributes&FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		m |= os.ModeSymlink
	}

	return m
}

func (fs *FileStat) ModTime() time.Time {
	return fs.LastWriteTime
}

func (fs *FileStat) IsDir() bool {
	return fs.Mode().IsDir()
}

func (fs *FileStat) Sys() interface{} {
	return fs
}
