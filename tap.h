/*
 * tap.h: function prototypes
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

long ioctlif(struct file *fileptr, unsigned int cmd, unsigned long arg);
struct socket *socketif(int family, int type, int protocol);
inline int recvfrom(void *arg);
int enable_iface(char *ifname);
int disable_iface(char *ifname);
int create_bridge(char *brname);
int destroy_bridge(char *brname);
int br_add_interface(const char *bridge, const char *dev);
int br_del_interface(const char *bridge, const char *dev);
int tuntap_iface_init(struct file **tunfptr, char *ifname);
