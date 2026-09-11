/*
 * MIT License
 *
 * Copyright (c) 2021 ProjectDiscovery, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

package io.projectdiscovery.utils.gui;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.swing.JPanel;
import javax.swing.JTabbedPane;

class SwingUtilsTest {

    @Test
    void testSelectsTabWhenTheComponentIsTheTabItself() {
        final JTabbedPane tabbedPane = new JTabbedPane();
        final JPanel first = new JPanel();
        final JPanel second = new JPanel();
        tabbedPane.addTab("first", first);
        tabbedPane.addTab("second", second);
        tabbedPane.setSelectedComponent(first);

        Assertions.assertTrue(SwingUtils.selectEnclosingTab(second));
        Assertions.assertSame(second, tabbedPane.getSelectedComponent());
    }

    @Test
    void testSelectsTabWhenTheComponentIsNested() {
        // Burp wraps the component it is handed, so the tabbed pane is not the direct parent.
        final JTabbedPane tabbedPane = new JTabbedPane();
        final JPanel first = new JPanel();
        final JPanel wrapper = new JPanel();
        final JPanel nested = new JPanel();
        wrapper.add(nested);
        tabbedPane.addTab("first", first);
        tabbedPane.addTab("wrapper", wrapper);
        tabbedPane.setSelectedComponent(first);

        Assertions.assertTrue(SwingUtils.selectEnclosingTab(nested));
        Assertions.assertSame(wrapper, tabbedPane.getSelectedComponent());
    }

    @Test
    void testSelectsTheClosestEnclosingTabbedPane() {
        final JTabbedPane outer = new JTabbedPane();
        final JTabbedPane inner = new JTabbedPane();
        final JPanel outerFirst = new JPanel();
        final JPanel innerFirst = new JPanel();
        final JPanel target = new JPanel();

        inner.addTab("innerFirst", innerFirst);
        inner.addTab("target", target);
        inner.setSelectedComponent(innerFirst);

        outer.addTab("outerFirst", outerFirst);
        outer.addTab("inner", inner);
        outer.setSelectedComponent(outerFirst);

        Assertions.assertTrue(SwingUtils.selectEnclosingTab(target));
        Assertions.assertSame(target, inner.getSelectedComponent());
        // Only the closest pane is touched, so the caller decides about the outer one.
        Assertions.assertSame(outerFirst, outer.getSelectedComponent());
    }

    @Test
    void testReturnsFalseWithoutAnEnclosingTabbedPane() {
        final JPanel orphan = new JPanel();
        new JPanel().add(orphan);

        Assertions.assertFalse(SwingUtils.selectEnclosingTab(orphan));
    }
}
