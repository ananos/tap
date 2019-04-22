/*
 * tap.c: simple kernel module to create tap & bridge interfaces
 *
 * Copyright (c) 2019
 * 		Author: Anastassios Nanos <anastassios.nanos@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/version.h>

#include <linux/fs.h>
#include <linux/uaccess.h>
#include <uapi/linux/if.h>
#include <uapi/linux/if_tun.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/in.h>
#include <linux/inet.h>
#include <net/sock.h>
#include <linux/net.h>
#include <linux/inetdevice.h>

#define TAP_FILE_PATH "/dev/net/tun"

static mm_segment_t oldfs;
struct file *tunfileptr;

char *tapname = "tap12";
char *brname = "br12";

long ioctlif(struct file *fileptr, unsigned int cmd, unsigned long arg)
{
    int ret = -EINVAL;

    if (!fileptr) {
        printk("fileptr is NULL\n");
        goto out;
    }

    if (!fileptr->f_op) {
        printk("no fileptr->f_ops\n");
        goto out;
    }

    oldfs = get_fs();
    set_fs(KERNEL_DS);
    ret = fileptr->f_op->unlocked_ioctl(fileptr, cmd, arg);
    set_fs(oldfs);

  out:
    return ret;
}

struct socket *socketif(int family, int type, int protocol)
{
    int ret;
    struct socket *socket = NULL;
    struct file *fp = NULL;

    printk("%s: enter: \n", __func__);
    ret = sock_create(family, type, protocol, &socket);

    if (ret < 0) {
        printk("sock_create failed ret:%d\n", ret);
        goto out;
    }

    fp = sock_alloc_file(socket, 0, NULL);
    if (!fp) {
        printk("sock_alloc failed\n");
        goto out;
    }

    printk("%s: exit: \n", __func__);
    return socket;

  out:
    if (socket) {
        sock_release(socket);
    }
    return NULL;
}

static int enable_iface(char *ifname)
{
    int ret = -EINVAL;
    struct ifreq ifr = { };
    struct socket *socket = NULL;
    struct file *fileptr = NULL;

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    ifr.ifr_addr.sa_family = AF_INET;

    socket = socketif(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (!socket) {
        printk("socket create null\n");
        goto out;
    }
    fileptr = socket->file;
    ret = ioctlif(fileptr, SIOCGIFFLAGS, (unsigned long) &ifr);
    if (ret < 0) {
        printk("get flags failed, ret:%d\n", ret);
        goto out;
    }

    ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);

    ret = ioctlif(fileptr, SIOCSIFFLAGS, (unsigned long) &ifr);
    if (ret < 0) {
        printk("set flags failed, ret:%d\n", ret);
        goto out;
    }
    sock_release(socket);

    return 0;

  out:
    if (socket) {
        sock_release(socket);
    }
    return ret;
}

static int disable_iface(char *ifname)
{
    int ret = -EINVAL;
    struct ifreq ifr = { };
    struct socket *socket = NULL;
    struct file *fileptr = NULL;

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    ifr.ifr_addr.sa_family = AF_INET;

    socket = socketif(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (!socket) {
        printk("socket create null\n");
        goto out;
    }
    fileptr = socket->file;
    ret = ioctlif(fileptr, SIOCGIFFLAGS, (unsigned long) &ifr);
    if (ret < 0) {
        printk("get flags failed, ret:%d\n", ret);
        goto out;
    }

    ifr.ifr_flags = ifr.ifr_flags & ~IFF_UP;

    ret = ioctlif(fileptr, SIOCSIFFLAGS, (unsigned long) &ifr);
    if (ret < 0) {
        printk("set flags failed, ret:%d\n", ret);
        goto out;
    }
    sock_release(socket);

    return 0;

  out:
    if (socket) {
        sock_release(socket);
    }
    return ret;
}

static int create_bridge(char *brname)
{
    int ret = -EINVAL;
    struct file *fileptr = NULL;
    struct socket *socket = NULL;

    printk("%s: enter: \n", __func__);
    if ((socket = socketif(AF_LOCAL, SOCK_STREAM, 0)) == NULL) {
        printk("error creating socket\n");
        goto out;
    }

    fileptr = socket->file;
    ret = ioctlif(fileptr, SIOCBRADDBR, (unsigned long) brname);
    if (ret < 0) {
        printk("create bridge failed, ret:%d\n", ret);
        goto out;
    }

    ret = 0;

    printk("%s: exit: \n", __func__);

  out:
    return ret;
}

static int destroy_bridge(char *brname)
{
    int ret = -EINVAL;
    struct file *fileptr = NULL;
    struct socket *socket = NULL;

    printk("%s: enter: \n", __func__);
    if ((socket = socketif(AF_LOCAL, SOCK_STREAM, 0)) == NULL) {
        printk("error creating socket\n");
        goto out;
    }

    fileptr = socket->file;
    ret = ioctlif(fileptr, SIOCBRDELBR, (unsigned long) brname);
    if (ret < 0) {
        printk("destroy bridge failed, ret:%d\n", ret);
        goto out;
    }

    ret = 0;
    printk("%s: exit: \n", __func__);

  out:
    return ret;
}

int br_add_interface(const char *bridge, const char *dev)
{
    struct ifreq ifr;
    int ret = -EINVAL;
    struct net_device *tapdev = dev_get_by_name(&init_net, dev);
    int ifindex = tapdev->ifindex;
    struct file *fileptr = NULL;
    struct socket *socket = NULL;

    if (ifindex == 0) {
        ret = -ENODEV;
        goto out;
    }

    strncpy(ifr.ifr_name, bridge, IFNAMSIZ);

    ifr.ifr_ifindex = ifindex;

    if ((socket = socketif(AF_LOCAL, SOCK_STREAM, 0)) == NULL) {
        printk("error creating socket\n");
        goto out;
    }

    fileptr = socket->file;

    ret = ioctlif(fileptr, SIOCBRADDIF, (unsigned long) &ifr);
    if (ret < 0) {
        printk("error adding iface:%s to br:%s\n", dev, bridge);
        goto out;
    }
    dev_put(tapdev);
  out:
    return ret;
}

int br_del_interface(const char *bridge, const char *dev)
{
    struct ifreq ifr;
    int ret = -EINVAL;
    struct net_device *tapdev = dev_get_by_name(&init_net, dev);
    int ifindex = tapdev->ifindex;
    struct file *fileptr = NULL;
    struct socket *socket = NULL;

    if (ifindex == 0) {
        ret = -ENODEV;
        goto out;
    }

    strncpy(ifr.ifr_name, bridge, IFNAMSIZ);

    ifr.ifr_ifindex = ifindex;

    if ((socket = socketif(AF_LOCAL, SOCK_STREAM, 0)) == NULL) {
        printk("error creating socket\n");
        goto out;
    }

    fileptr = socket->file;

    ret = ioctlif(fileptr, SIOCBRDELIF, (unsigned long) &ifr);
    if (ret < 0) {
        printk("error deleting iface:%s from br:%s\n", dev, bridge);
        goto out;
    }
    dev_put(tapdev);
  out:
    return ret;
}

static int tuntap_iface_init(struct file **tunfptr, char *ifname)
{
    int ret = -EINVAL;
    struct file *fileptr;
    unsigned long flags;

    struct ifreq ifr;

    printk("%s: enter: \n", __func__);

    oldfs = get_fs();
    set_fs(KERNEL_DS);

    fileptr = filp_open(TAP_FILE_PATH, O_RDWR, 0);
    set_fs(oldfs);
    if (!fileptr) {
        printk("error opening file\n");
        goto out;
    }
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    flags = IFF_TAP | IFF_NO_PI;
    ifr.ifr_flags = flags;
    ret = ioctlif(fileptr, TUNSETIFF, (unsigned long) &ifr);
    if (ret < 0) {
        printk("tap iface create failed, reg:%d\n", ret);
        goto out;
    }

    *tunfptr = fileptr;
  out:
    printk("%s: exit: ret:%d\n", __func__, ret);
    return ret;
}

static int __init tuntap_init(void)
{
    int ret = -EINVAL;

    printk("Init tuntap\n");

    ret = tuntap_iface_init(&tunfileptr, tapname);
    if (ret < 0) {
        printk("error creating %s\n", tapname);
        goto out;
    }
    ret = create_bridge(brname);
    if (ret < 0) {
        printk("error creating %s\n", brname);
        goto out;
    }

    enable_iface(tapname);
    enable_iface(brname);
    ret = br_add_interface(brname, tapname);
    //ret = br_add_interface(brname, "eth1");
  out:
    return ret;
}

static void __exit tuntap_exit(void)
{
    br_del_interface(brname, tapname);
    disable_iface(tapname);
    disable_iface(brname);

    if (tunfileptr) {
        filp_close(tunfileptr, 0);
    }
    destroy_bridge(brname);
    printk("tuntap exit ok");
    return;
}

MODULE_LICENSE("GPL");
module_init(tuntap_init);
module_exit(tuntap_exit);
