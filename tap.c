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
#include <linux/if_tun.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/in.h>
#include <linux/inet.h>
#include <net/sock.h>
#include <linux/kthread.h>
#include <linux/net.h>
#include <linux/inetdevice.h>

#include "tap.h"

static mm_segment_t oldfs;
struct file *tunfileptr;
struct task_struct *t;

char *tapname = "tap12";
char *brname = "br12";

static int __init tuntap_init(void)
{
    int ret = -EINVAL;
    char thrname[20];
    struct socket *socket;

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
    //enable_iface("eth1");
    ret = br_add_interface(brname, tapname);
    //ret = br_add_interface(brname, "eth1");     /* temp 2nd interface to have some traffic */

    struct net_device *tapdev = dev_get_by_name(&init_net, tapname);
    //int ifindex = tapdev->ifindex;

    sprintf(thrname, "recv-%s", tapname);

    if ((socket = socketif(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == NULL) {
        printk("error creating socket\n");
        goto out;
    }
    oldfs = get_fs();
    set_fs(KERNEL_DS);
    ret = sock_setsockopt(socket, SOL_SOCKET, SO_BINDTODEVICE, tapname, IFNAMSIZ - 1);
    set_fs(oldfs);
    if (ret < 0) {
        printk("setsockoptp SO_BINDTODEVICE, reg:%d\n", ret);
        goto out;
    }

    dev_put(tapdev);
    /* temp thread to understand how to capture eth frames */
    t = kthread_run(recvfrom, (void *) socket, thrname);

  out:
    return ret;
}

static void __exit tuntap_exit(void)
{
    kthread_stop(t);
    //br_del_interface(brname, "eth1");
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
