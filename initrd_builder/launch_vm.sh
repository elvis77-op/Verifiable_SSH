virsh destroy initrd_grpc_v1 
virsh undefine initrd_grpc_v1
virt-install   --name initrd_grpc_v1 \
 --memory 2048   --vcpus 2  \
  --disk path=/root/att.qcow2,size=40,format=qcow2  \
   --network network=default   --graphics none  \
    --console pty,target_type=serial  \
     --os-variant generic\
        --boot kernel=/boot/vmlinuz-$(uname -r),initrd=output/initramfs.cpio.gz,kernel_args="console=ttyS0 root=/dev/vda"